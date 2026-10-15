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
import sys
import threading
import time
from zoneinfo import ZoneInfo

import yaml
from convert_findings import convert
from evaluate_run import evaluate
from request_guard import DEFAULT_SETTINGS, load_settings
from target_claims import ClaimBusy, TargetClaim
from vvaharness.config import load

ROOT = pathlib.Path(__file__).resolve().parents[1]
RUN_TIMEZONE = ZoneInfo("America/New_York")
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
                code = proc.wait(timeout=1200)
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


def has_unrecovered_stage_errors(report_directory):
    for path in report_directory.glob("*_errors.jsonl"):
        for line in path.read_text().splitlines():
            if not line.strip():
                continue

            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                return True

            if not isinstance(event, dict) or event.get("recovered") is not True:
                return True

    return False


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


def run_directory_name(target, when):
    if when.tzinfo is None or when.utcoffset() is None:
        raise ValueError("Run timestamps must include a timezone")

    local = when.astimezone(RUN_TIMEZONE)
    repository = "-".join(target["repo_url"].rstrip("/").removesuffix(".git").split("/")[-2:])
    repository = re.sub(r"[^A-Za-z0-9._-]+", "-", repository)
    return (
        f"{local:%Y-%m-%d_%H-%M-%S}_{target['commit'][:12]}_"
        f"{repository}_{local:%Z}"
    )


def create_run_directory(target, when=None):
    when = when or datetime.datetime.now(datetime.timezone.utc)
    base = run_directory_name(target, when)
    parent = ROOT / "runs"
    parent.mkdir(parents=True, exist_ok=True)
    index = 1
    while True:
        name = base if index == 1 else f"{base}_{index:02d}"
        run = parent / name
        try:
            run.mkdir()
        except FileExistsError:
            index += 1
        else:
            return run


def run_target(t, settings=None, extra_overlay=None, claim=None):
    custom = settings is not None or extra_overlay is not None
    settings = dict(settings or DEFAULT_SETTINGS)
    run = create_run_directory(t)
    if claim is not None:
        claim.update(run_directory=str(run.relative_to(ROOT)))

    write(run / "execution.json", {
        "hostname": socket.gethostname(),
        "pid": os.getpid(),
        "claim": claim.owner if claim is not None else None,
    })
    write(run / "target.json", t)
    write(run / "model-config.json", settings)
    profile = model_profile(run, settings, extra_overlay) if custom else PROFILE
    effective = load(profile)
    budget_fields = {
        "max_tokens", "replay_max_tokens", "auto_exclude_max_tokens", "parallel",
        "deadline", "batch_deadline", "batch_wall_clock_ceiling",
        "timeout", "replay_timeout", "resume_timeout",
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
            stage_errors = has_unrecovered_stage_errors(scan / "security-scan")
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


def experiment_key(settings, extra_overlay, provenance):
    revision_path = pathlib.Path(settings["model_dir"]) / "MODEL_REVISION.txt"
    identity = {
        "model": settings,
        "model_revision": revision_path.read_text().strip() if revision_path.exists() else None,
        "upstream": {name: item["commit"] for name, item in provenance.items()},
        "baseline": (ROOT / "configs/baseline.local.yaml").read_text(),
        "profile": PROFILE.read_text(),
        "overlay": extra_overlay.read_text() if extra_overlay else None,
    }
    return hashlib.sha256(json.dumps(identity, sort_keys=True).encode()).hexdigest()


def completed_targets(settings, extra_overlay, provenance):
    """Recognize completed matching runs created before shared claims existed."""
    done = set()
    for status_path in (ROOT / "runs").glob("*/status.json"):
        directory = status_path.parent
        try:
            if json.loads(status_path.read_text())["status"] != "completed":
                continue

            if (directory / "baseline.local.yaml").read_bytes() != (ROOT / "configs/baseline.local.yaml").read_bytes():
                continue

            revisions = json.loads((directory / "revisions.json").read_text())
            if any(revisions.get(name) != item["commit"] for name, item in provenance.items()):
                continue

            if json.loads((directory / "model-config.json").read_text()) != settings:
                continue

            revision_path = pathlib.Path(settings["model_dir"]) / "MODEL_REVISION.txt"
            model_revision = revision_path.read_text().strip() if revision_path.exists() else None
            if revisions.get("model") != model_revision:
                continue

            if (directory / "upstream-profile.yaml").read_bytes() != PROFILE.read_bytes():
                continue

            saved_overlay = directory / "profile-overlay.yaml"
            if extra_overlay is None:
                if saved_overlay.exists():
                    continue

            elif not saved_overlay.exists() or saved_overlay.read_bytes() != extra_overlay.read_bytes():
                continue

            done.add(json.loads((directory / "target.json").read_text())["target_id"])
        except (OSError, ValueError, KeyError, TypeError):
            # Incomplete run metadata never establishes a completed scan.
            continue

    return done


def process_targets(targets, settings, extra_overlay, provenance, *,
                    retry_failed=False, rerun_completed=False, prepare_missing=False):
    effective_settings = settings or DEFAULT_SETTINGS
    experiment = experiment_key(effective_settings, extra_overlay, provenance)
    historical_done = completed_targets(effective_settings, extra_overlay, provenance)
    outcomes = []
    for entry in targets:
        target = {key: entry[key] for key in ("target_id", "repo_url", "commit")}
        target_id = target["target_id"]
        try:
            with TargetClaim(ROOT / "runs", target, experiment) as claim:
                previous = claim.previous()
                completed = (
                    previous is not None and previous["status"] == "completed"
                ) or target_id in historical_done
                if completed and not rerun_completed:
                    outcome = "skipped_completed"
                elif previous and previous["status"] in ("failed", "interrupted") and not retry_failed:
                    outcome = "skipped_failed"
                else:
                    print(f"[queue] Claimed {target_id}: {target['repo_url']} @ {target['commit']}", flush=True)
                    source = ROOT / "targets" / target_id
                    if not source.exists() and prepare_missing:
                        from prepare_targets import prepare

                        print(f"[prepare] Fetching {target_id}", flush=True)
                        prepare(target)

                    if not source.is_dir():
                        raise RuntimeError("Target not prepared; use --prepare-missing or prepare_targets.py")

                    outcome = run_target(target, settings, extra_overlay, claim=claim)
                    claim.finish(outcome)

        except ClaimBusy as error:
            outcome = "skipped_running"
            print(f"[queue] {target_id}: claimed by another worker ({error}/owner.json)", flush=True)
        except Exception as error:
            outcome = "failed"
            print(f"[queue] {target_id}: {error}", flush=True)

        print(f"[queue] {target_id}: {outcome}", flush=True)
        outcomes.append({"target_id": target_id, "status": outcome})

    print("[queue] No more available targets in the selected range; stopping.", flush=True)
    return outcomes


def queue_status():
    active = []
    attempts = []
    for pattern, destination in ((".claims/*", active), (".target-status/*/*.json", attempts)):
        for path in sorted((ROOT / "runs").glob(pattern)):
            if destination is active:
                path = path / "owner.json"

            try:
                destination.append(dict(json.loads(path.read_text()), metadata_path=str(path)))
            except (OSError, ValueError):
                destination.append({"metadata_path": str(path), "status": "unavailable"})

    print(json.dumps({"active_claims": active, "latest_attempts": attempts}, indent=2))
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--limit", type=int, help="Number of manifest candidates to consider, including skipped targets")
    parser.add_argument("--offset", default=0, type=int)
    parser.add_argument("--resume", action="store_true", help="Compatibility option: matching completed targets are now always skipped")
    parser.add_argument("--retry-failed", action="store_true", help="Allow a new attempt for targets this scheduler recorded as failed/interrupted")
    parser.add_argument("--rerun-completed", action="store_true", help="Explicitly allow new attempts for matching completed targets")
    parser.add_argument("--prepare-missing", action="store_true", help="Fetch missing sources after claiming each target")
    parser.add_argument("--profile-overlay", type=pathlib.Path)
    parser.add_argument("--model-config", type=pathlib.Path, help="Local model experiment settings")
    parser.add_argument("--status", action="store_true", help="Show shared claims and latest attempts without starting work")
    args = parser.parse_args()
    if args.status:
        return queue_status()

    if args.limit is None or not 1 <= args.limit <= 166 or args.offset < 0:
        parser.error("limit 1..166 and offset >=0 required")

    if OVERLAY.read_bytes() != (ROOT / "configs/baseline.local.yaml").read_bytes():
        raise SystemExit("Baseline overlay mismatch")

    provenance = json.loads((ROOT / "configs/upstream-revisions.json").read_text())
    if any(upstream_changes().values()):
        raise SystemExit("Saved upstream source checksum mismatch")

    settings = load_settings(args.model_config) if args.model_config else None
    overlay = args.profile_overlay.resolve() if args.profile_overlay else None
    manifest = json.loads((ROOT / "datasets/manifest.json").read_text())
    outcomes = process_targets(
        manifest["targets"][args.offset : args.offset + args.limit], settings, overlay, provenance,
        retry_failed=args.retry_failed,
        rerun_completed=args.rerun_completed,
        prepare_missing=args.prepare_missing,
    )
    print(json.dumps(outcomes))
    return 1 if any(item["status"] in ("failed", "skipped_failed") for item in outcomes) else 0


def cli():
    if "--status" in sys.argv[1:]:
        return main()

    runs = ROOT / "runs"
    runs.mkdir(exist_ok=True)
    # Shared mode fences older exclusive-lock runners without serializing new servers.
    with (runs / ".runner.lock").open("a+") as legacy_lock:
        try:
            fcntl.flock(legacy_lock, fcntl.LOCK_SH | fcntl.LOCK_NB)
        except BlockingIOError:
            raise SystemExit("An older runner is active; stop it before using shared scheduling")

        host_key = hashlib.sha256(socket.gethostname().encode()).hexdigest()
        hosts = runs / ".host-locks"
        hosts.mkdir(exist_ok=True)
        with (hosts / f"{host_key}.lock").open("a") as host_lock:
            try:
                fcntl.flock(host_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SystemExit("Another runner is active on this host (local proxy port 8003)")

            return main()


def terminate(signum, frame):
    raise KeyboardInterrupt("Runner terminated")


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, terminate)
    raise SystemExit(cli())
