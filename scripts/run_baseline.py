#!/usr/bin/env python3
"""Resumable target controller; upstream VVAH budgets, unique runs, isolated annotations."""

import argparse
import datetime
import fcntl
import hashlib
import json
import os
import pathlib
import re
import shutil
import signal
import socket
import subprocess
import threading
import time

import yaml
from convert_findings import convert
from evaluate_run import evaluate
from request_guard import DEFAULT_SETTINGS, load_settings
from vvaharness.config import load

ROOT = pathlib.Path(__file__).resolve().parents[1]
PROFILE = (
    ROOT
    / "harnesses/visa-vulnerability-agentic-harness/vvaharness/config/profiles/default.yaml"
)
OVERLAY = PROFILE.parent / "config.local.yaml"


def write(path, obj):
    path.write_text(json.dumps(obj, indent=2) + "\n")


def command(cmd, cwd, env, log):
    label = log.stem
    started = time.monotonic()
    current_stage = ["starting"]
    print(f"[{label}] Starting; limits controlled by VVAH; log: {log}", flush=True)
    with log.open("w") as f:
        proc = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=dict(env, PYTHONUNBUFFERED="1"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            start_new_session=True,
        )

        def read_output():
            for line in proc.stdout:
                f.write(line)
                f.flush()
                event = re.search(r"\[progress\]\s+stage-(start|done)\s+(\S+)", line)
                if event:
                    action, stage = event.groups()
                    if action == "start":
                        current_stage[0] = stage
                    elif stage == "s0":
                        current_stage[0] = "code graph preparation before S1"
                    else:
                        current_stage[0] = f"{stage} completed; preparing next stage"

                elif "[auto-step1] surveying" in line:
                    current_stage[0] = "auto-step1 repository survey"
                elif "[probe]" in line:
                    current_stage[0] = "model preflight"

                if any(tag in line for tag in (
                    "[progress]", "[probe]", "[auto-step1]", "[graphdb]",
                    "scan failed:", "▶ [", "✓ [", "✗ [", "⚠ [",
                )):
                    print(f"[{label}] {line.strip()}", flush=True)


        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        while True:
            try:
                code = proc.wait(timeout=30)
                break
            except subprocess.TimeoutExpired:
                elapsed = time.monotonic() - started
                print(
                    f"[{label}] {elapsed:.0f}s elapsed; "
                    f"stage: {current_stage[0]}", flush=True,
                )
            except KeyboardInterrupt:
                os.killpg(proc.pid, signal.SIGTERM)
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                reader.join(timeout=5)
                raise

        reader.join(timeout=5)
        if not reader.is_alive():
            proc.stdout.close()

        print(
            f"[{label}] Finished; exit {code}; "
            f"elapsed {time.monotonic() - started:.1f}s", flush=True,
        )
        return code


def failure_reason(codes):
    code = codes.get("scan_retry", codes.get("scan"))
    if code not in (None, 0):
        return f"VVAH detection exited with code {code}; see scan logs"

    return "Detection did not produce a complete, non-degraded report; see scan logs"


def provider_errors(run):
    errors = {}
    path = run / "tool-trace.jsonl"
    if not path.exists():
        return errors

    for line in path.read_text().splitlines():
        record = json.loads(line)
        if record.get("status", 200) < 400:
            continue

        message = record.get("error")
        if not message:
            try:
                message = json.loads(record.get("response", "{}"))["error"]["message"]
            except (KeyError, ValueError, TypeError):
                message = f"Provider HTTP {record['status']}"

        errors[message] = errors.get(message, 0) + 1
    return errors


def snapshot(path):
    return {
        str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in path.rglob("*")
        if p.is_file() and not p.is_symlink()
    }


def upstream_changes():
    provenance = json.loads((ROOT / "configs/upstream-revisions.json").read_text())
    changes = {}
    for name, source in provenance.items():
        current = ROOT / source["path"]
        changes[name] = []
        for relative, expected in source["sha256"].items():
            path = current / relative
            actual = (
                hashlib.sha256(path.read_bytes()).hexdigest()
                if path.is_file()
                else None
            )
            if actual != expected:
                changes[name].append(
                    {"path": relative, "expected": expected, "actual": actual}
                )

    return changes


def model_profile(run, settings, extra_overlay=None):
    directory = run / "profiles"
    directory.mkdir()
    profile = yaml.safe_load(PROFILE.read_text())
    for key, value in profile.get("inject", {}).items():
        if value:
            profile["inject"][key] = str((PROFILE.parent / value).resolve())

    (directory / "default.yaml").write_text(yaml.safe_dump(profile, sort_keys=False))
    overlay = yaml.safe_load((ROOT / "configs/baseline.local.yaml").read_text())
    if extra_overlay:
        additions = yaml.safe_load(extra_overlay.read_text())
        allowed = {"step1", "step2", "step4", "step6_verify", "step7_dedup", "step8"}
        if not isinstance(additions, dict) or set(additions) - allowed:
            raise ValueError("Profile overlays may change detection stage controls only")

        for stage, values in additions.items():
            if not isinstance(values, dict) or values.get("bash") or any(
                tool in ("Bash", "Edit", "Write") for tool in values.get("allowed_tools", [])
            ):
                raise ValueError("Detection overlay must retain read-only tools")

            overlay.setdefault(stage, {}).update(values)
        shutil.copy2(extra_overlay, run / "profile-overlay.yaml")

    def adapt(node):
        if not isinstance(node, dict):
            return

        if "id" in node:
            node["id"] = settings["model_name"]

        for key, value in node.items():
            if isinstance(value, dict):
                adapt(value)

    adapt(overlay)
    path = directory / "config.local.yaml"
    path.write_text(yaml.safe_dump(overlay, sort_keys=False))
    path.chmod(0o600)
    return directory / "default.yaml"


def run_target(t, settings=None, extra_overlay=None):
    custom = settings is not None or extra_overlay is not None
    settings = dict(settings or DEFAULT_SETTINGS)
    run = (
        ROOT
        / "runs"
        / (
            datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            + "-"
            + t["target_id"]
        )
    )
    run.mkdir(parents=True)
    write(run / "target.json", t)
    write(run / "model-config.json", settings)
    profile = model_profile(run, settings, extra_overlay) if custom else PROFILE
    effective = load(profile)
    budget_fields = {
        "max_tokens", "replay_max_tokens", "auto_exclude_max_tokens", "parallel",
        "deadline", "timeout", "replay_timeout", "resume_timeout",
        "max_model_calls", "max_turns", "prompt_token_budget",
    }
    limits = {
        "context_total": settings["context_limit"],
        "scan_wall_seconds": None,
        "proxy_transport_timeout_seconds": None,
        "request_serialization": False,
        "sampling": "upstream VVAH/model-server settings; no wrapper overrides",
        "stage_limits": {
            name: {key: value for key, value in stage.items()
                   if key in budget_fields}
            for name, stage in effective._data.items()
            if name.startswith("step") and isinstance(stage, dict)
        },
    }
    write(run / "limits.json", limits)
    shutil.copy2(ROOT / "configs/baseline.local.yaml", run / "baseline.local.yaml")
    shutil.copy2(PROFILE, run / "upstream-profile.yaml")
    shutil.copy2(
        ROOT / "configs/harness-requirements.lock.txt",
        run / "harness-requirements.lock.txt",
    )
    provenance = json.loads((ROOT / "configs/upstream-revisions.json").read_text())
    revisions = {name: source["commit"] for name, source in provenance.items()}
    revisions["configuration_kind"] = (
        "profile-variant" if extra_overlay else "local-model" if custom else "baseline"
    )
    if extra_overlay:
        revisions["profile_overlay"] = {
            "path": str(extra_overlay),
            "sha256": hashlib.sha256(extra_overlay.read_bytes()).hexdigest(),
        }

    model_revision = pathlib.Path(settings["model_dir"]) / "MODEL_REVISION.txt"
    revisions["model"] = (
        model_revision.read_text().strip() if model_revision.exists() else None
    )
    revisions["effective_base_url"] = "http://127.0.0.1:8003/v1"
    revisions["upstream_base_url"] = settings["base_url"]
    revisions["integration"] = (
        "DeepAgents/OpenAI Chat Completions; context accounting/trace proxy; upstream execution budgets"
    )
    write(run / "revisions.json", revisions)
    write(
        run / "integration-hashes.json",
        {
            str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
            for folder in ("scripts", "configs")
            for p in (ROOT / folder).glob("*")
            if p.is_file()
        },
    )
    env = {
        k: v
        for k, v in os.environ.items()
        if not (
            k.startswith(
                (
                    "ANTHROPIC",
                    "EV_",
                    "VVAHARNESS_INGEST",
                    "LANGSMITH",
                    "LANGCHAIN",
                    "OPENAI",
                    "CLAUDE",
                )
            )
            or k
            in ("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "VVAHARNESS_NO_LOCAL_CONFIG")
        )
    }
    # Prevent ~/.env loading and external caches, credentials, or accidental telemetry.
    env.update(
        OPENAI_API_KEY="EMPTY",
        OPENAI_BASE_URL="http://127.0.0.1:8003/v1",
        NO_PROXY="127.0.0.1,localhost",
        no_proxy="127.0.0.1,localhost",
        HF_HUB_OFFLINE="1",
        TRANSFORMERS_OFFLINE="1",
        LANGSMITH_TRACING="false",
        LANGCHAIN_TRACING_V2="false",
        JAVA_TOOL_OPTIONS="-Xms128m -Xmx2g",
        TMPDIR=str(run / "tmp"),
        VVAHARNESS_STATE_DIR=str(run / "state"),
        XDG_CACHE_HOME=str(ROOT / ".cache"),
    )
    (run / ".env").write_text(
        "# Baseline: intentionally empty; prevent fallback to a user .env.\n"
    )
    (run / ".env").chmod(0o600)
    (run / "state").mkdir(mode=0o700)
    (run / "tmp").mkdir()
    target = ROOT / "targets" / t["target_id"]
    before = snapshot(target)
    write(run / "source-hashes-before.json", before)
    # Use a disposable scan copy: upstream outputs, skills and state never touch the canonical target.
    scan = run / "scan-source"
    shutil.copytree(target, scan, symlinks=True)
    guard_log = (run / "guard.log").open("w")
    guard = subprocess.Popen(
        [
            settings["tokenizer_python"],
            str(ROOT / "scripts/request_guard.py"),
            "--trace",
            str(run / "tool-trace.jsonl"),
            "--model-config",
            str(run / "model-config.json"),
        ],
        env=env,
        stdout=guard_log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    started = time.monotonic()
    codes = {}
    status = "failed"
    reason = None
    try:
        while True:
            if guard.poll() is not None:
                raise RuntimeError("Request guard failed to start; inspect guard.log")

            try:
                with socket.create_connection(("127.0.0.1", 8003)):
                    break
            except Exception:
                time.sleep(0.5)
        codes["estimate"] = command(
            [
                str(ROOT / ".venv/bin/vvaharness"),
                "estimate",
                "--repo",
                str(scan),
                "--config",
                str(profile),
            ],
            run,
            env,
            run / "estimate.log",
        )
        # Exercise the actual harness boundary even when the independent protocol probe failed.
        codes["scan"] = command(
            [
                str(ROOT / ".venv/bin/vvaharness"),
                "scan",
                "--repo",
                str(scan),
                "--config",
                str(profile),
                "--stop-after",
                "s9",
            ],
            run,
            env,
            run / "scan.log",
        )
        for message, count in provider_errors(run).items():
            print(f"[provider-error] {message} ({count} request(s))", flush=True)
        if codes["scan"] != 0:
            codes["setup"] = command(
                [str(ROOT / ".venv/bin/vvaharness"), "setup", "--config", str(profile)],
                run,
                env,
                run / "setup.log",
            )
            # Upstream operating instructions require one identical retry after setup.
            codes["scan_retry"] = command(
                [
                    str(ROOT / ".venv/bin/vvaharness"),
                    "scan",
                    "--repo",
                    str(scan),
                    "--config",
                    str(profile),
                    "--stop-after",
                    "s9",
                ],
                run,
                env,
                run / "scan-retry.log",
            )

        raw = scan / "security-scan/findings.json"
        print("[conversion] Reading the upstream findings report", flush=True)
        if raw.exists():
            shutil.copy2(raw, run / "raw-findings.json")
            report = json.loads(raw.read_text())
            rows, errors = convert(report, t)
            error_artifacts = list((scan / "security-scan").glob("*_errors.jsonl"))
            stage_errors = any(p.stat().st_size for p in error_artifacts)
            status = (
                "completed"
                if codes.get("scan_retry", codes["scan"]) == 0
                and not report.get("degraded")
                and not stage_errors
                else "failed"
            )
        else:
            rows = []
            errors = [
                {
                    "error": "No FinalReport produced; scan failure is not an empty successful prediction",
                    "missing_evidence": True,
                }
            ]

        (run / "converted.jsonl").write_text(
            "".join(json.dumps(x) + "\n" for x in rows)
        )
        (run / "conversion-errors.jsonl").write_text(
            "".join(json.dumps(x) + "\n" for x in errors)
        )
        reason = (
            None
            if status == "completed"
            else failure_reason(codes)
        )
    except Exception as e:
        reason = str(e)
        (run / "converted.jsonl").touch()
        (run / "conversion-errors.jsonl").write_text(
            json.dumps({"error": str(e), "missing_evidence": True}) + "\n"
        )
    finally:
        if guard.poll() is None:
            os.killpg(guard.pid, signal.SIGTERM)
            guard.wait(timeout=5)

        guard_log.close()
    after = snapshot(target)
    changed = before != after
    scan_changed = [
        k
        for k, v in before.items()
        if not (scan / k).is_file()
        or hashlib.sha256((scan / k).read_bytes()).hexdigest() != v
    ]
    if changed or scan_changed:
        status = "failed"
        reason = "Target source changed"

    write(
        run / "status.json",
        {
            "status": status,
            "reason": reason,
            "exit_codes": codes,
            "elapsed_seconds": time.monotonic() - started,
            "canonical_source_unchanged": not changed,
            "scan_source_changes": scan_changed,
            "token_usage": "reported usage in tool-trace.jsonl and upstream run manifests; absent values unavailable",
            "wall_limit_seconds": None,
        },
    )
    write(run / "source-hashes-after.json", after)
    write(run / "upstream-source-changes.json", upstream_changes())
    errors = provider_errors(run)
    write(run / "provider-errors.json", errors)
    if status != "completed" and any("Context budget exceeded" in message for message in errors):
        reason = "Model requests exceeded the configured context budget; see provider-errors.json"
        saved_status = json.loads((run / "status.json").read_text())
        saved_status["reason"] = reason
        write(run / "status.json", saved_status)

    print("[evaluation] Matching findings against the selected VulnGym subset", flush=True)
    evaluate(run)
    if status == "failed" and not (scan / "security-scan").exists():
        shutil.rmtree(scan)

    print(run, flush=True)
    print(f"[result] {status}: {reason or 'detection and evaluation completed'}", flush=True)
    return status


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--limit", required=True, type=int)
    p.add_argument("--offset", default=0, type=int)
    p.add_argument("--resume", action="store_true")
    p.add_argument("--profile-overlay", type=pathlib.Path)
    p.add_argument(
        "--model-config",
        type=pathlib.Path,
        help="Separate local-model experiment settings; baseline configuration stays unchanged",
    )
    a = p.parse_args()
    if not 1 <= a.limit <= 166 or a.offset < 0:
        p.error("limit 1..166 and offset >=0 required")

    if OVERLAY.read_bytes() != (ROOT / "configs/baseline.local.yaml").read_bytes():
        raise SystemExit("Baseline overlay mismatch")

    provenance = json.loads((ROOT / "configs/upstream-revisions.json").read_text())
    if any(upstream_changes().values()):
        raise SystemExit("Saved upstream source checksum mismatch")

    settings = load_settings(a.model_config) if a.model_config else None
    extra_overlay = a.profile_overlay.resolve() if a.profile_overlay else None
    manifest = json.loads((ROOT / "datasets/manifest.json").read_text())
    done = set()
    if a.resume:
        for s in (ROOT / "runs").glob("*/status.json"):
            if (
                json.loads(s.read_text())["status"] == "completed"
                and (s.parent / "baseline.local.yaml").read_bytes()
                == (ROOT / "configs/baseline.local.yaml").read_bytes()
            ):
                rev = json.loads((s.parent / "revisions.json").read_text())
                if (
                    rev.get("harness") == provenance["harness"]["commit"]
                    and rev.get("dataset") == provenance["dataset"]["commit"]
                    and (s.parent / "model-config.json").is_file()
                    and json.loads((s.parent / "model-config.json").read_text())
                    == (settings or DEFAULT_SETTINGS)
                    and (
                        (extra_overlay is None and not (s.parent / "profile-overlay.yaml").exists())
                        or (extra_overlay is not None
                            and (s.parent / "profile-overlay.yaml").exists()
                            and (s.parent / "profile-overlay.yaml").read_bytes() == extra_overlay.read_bytes())
                    )
                ):
                    done.add(
                        json.loads((s.parent / "target.json").read_text())["target_id"]
                    )

    outcomes = []
    for g in manifest["targets"][a.offset : a.offset + a.limit]:
        if g["target_id"] in done:
            outcomes.append(
                {"target_id": g["target_id"], "status": "skipped_completed"}
            )
            continue

        t = {k: g[k] for k in ("target_id", "repo_url", "commit")}
        if not (ROOT / "targets" / g["target_id"]).exists():
            raise SystemExit(
                "Target not prepared: run prepare_targets.py with matching bounds"
            )

        outcomes.append(
            {
                "target_id": g["target_id"],
                "status": run_target(t, settings, extra_overlay),
            }
        )
    print(json.dumps(outcomes))
    return (
        0
        if all(o["status"] in ("completed", "skipped_completed") for o in outcomes)
        else 1
    )


if __name__ == "__main__":
    (ROOT / "runs").mkdir(exist_ok=True)
    with (ROOT / "runs/.runner.lock").open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("Another baseline runner is active")
        raise SystemExit(main())

