#!/usr/bin/env python3
"""Run VVAH detection on one CryptoAPI-Bench Java file at a time, with stage logs."""

import argparse
import datetime
import hashlib
import json
import os
import re
import signal
import sqlite3
import subprocess
import sys
import threading
import time
from contextvars import ContextVar
from pathlib import Path
from zoneinfo import ZoneInfo

import yaml

ROOT = Path(__file__).resolve().parents[1]
MODEL = "qwen35-9b"
BASE_URL = "http://127.0.0.1:8005/v1"
MODEL_DIR = Path("/home/spl/akram/local_models/qwen3.5-9b")
OUTPUT_TOKENS = 131072


# Save readable UTF-8 JSON for run metadata and stage outputs.
def write_json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


# Find Java inputs in a stable order without reading benchmark annotations.
def input_files(dataset):
    files = sorted((dataset / "src/main/java").rglob("*.java"))
    if not files:
        raise ValueError("Dataset has no Java sources; run download_cryptoapi_bench.py first")

    return files


def profile(harness):
    """Use upstream detection with explicit local routing, output budgets, and serial work."""
    source = harness / "vvaharness/config/profiles/default.yaml"
    config = yaml.safe_load(source.read_text(encoding="utf-8"))

    # Route every model role, including nested roles, to the same local endpoint.
    def local_roles(node):
        if "id" in node:
            node.update(id=MODEL, via="deepagents", provider="openai", use_responses_api=False, max_tokens=OUTPUT_TOKENS)

        for value in node.values():
            if isinstance(value, dict):
                local_roles(value)

    local_roles(config["models"])
    config["openai"] = {"api_key": "EMPTY", "base_url": BASE_URL, "no_proxy": "127.0.0.1,localhost"}
    config["sdk"] = {"cache_markers": "off"}
    config["cache_markers"] = "off"
    config["inject"] = {}
    config["step1"]["auto_exclude_max_tokens"] = OUTPUT_TOKENS
    for name in ("step2", "step4", "step6_verify", "step7_dedup", "step8"):
        config[name]["max_tokens"] = OUTPUT_TOKENS
        if "replay_max_tokens" in config[name]:
            config[name]["replay_max_tokens"] = OUTPUT_TOKENS

    config["step4"]["parallel"] = 1
    config["step6_verify"]["parallel"] = 1
    config["step6_exploit_verification"]["enabled"] = False
    config["step_remediate"]["enabled"] = False
    config["step_validate"]["enabled"] = False
    config["scan_progress"] = {"enabled": True, "style": "verbose"}
    config["output"].update(ingest_url="", ingest_token="")
    return config


# Register local callbacks that record model and tool activity by VVAH stage.
def install_model_logging(directory):
    """Observe LangChain calls locally; never modify their inputs or outputs."""
    from langchain_core.callbacks import BaseCallbackHandler
    from langchain_core.tracers.context import register_configure_hook
    from vvaharness.util.tokens import TOKENS

    class StageTrace(BaseCallbackHandler):
        run_inline = True
        lock = threading.Lock()
        phases = {}

        # Append an event to its stage log while keeping concurrent writes together.
        def emit(self, kind, run_id, data, parent_run_id=None):
            key = str(run_id)
            with self.lock:
                phase = self.phases.setdefault(key, TOKENS.current_phase() or "preflight")
                stage = re.match(r"s[0-9]+", phase)
                stage = stage[0] if stage else "preflight"
                folder = directory / "stages" / stage
                folder.mkdir(parents=True, exist_ok=True)
                row = {"time": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                       "phase": phase, "event": kind, "run_id": key, "parent_run_id": str(parent_run_id) if parent_run_id else None,
                       "data": data}
                with (folder / "model-events.jsonl").open("a", encoding="utf-8") as stream:
                    stream.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")

        # Record model messages and selected request settings, excluding credentials.
        def on_chat_model_start(self, serialized, messages, *, run_id, parent_run_id=None, **kwargs):
            params = kwargs.get("invocation_params", {})
            allowed = {"model", "model_name", "temperature", "top_p", "max_tokens", "max_completion_tokens",
                       "tools", "tool_choice", "response_format", "reasoning_effort", "stop"}
            self.emit("model_input", run_id, {
                "messages": [[message.model_dump(mode="json") for message in batch] for batch in messages],
                "parameters": {key: value for key, value in params.items() if key in allowed},
            }, parent_run_id)

        # Save the generated response and any usage or completion metadata it reports.
        def on_llm_end(self, response, *, run_id, parent_run_id=None, **kwargs):
            self.emit("model_output", run_id, response.model_dump(mode="json"), parent_run_id)

        # Record a failed model request with its request and parent identifiers.
        def on_llm_error(self, error, *, run_id, parent_run_id=None, **kwargs):
            self.emit("model_error", run_id, str(error), parent_run_id)

        # Record the selected tool and the input supplied to it.
        def on_tool_start(self, serialized, input_str, *, run_id, parent_run_id=None, **kwargs):
            self.emit("tool_input", run_id, {"name": (serialized or {}).get("name"), "input": input_str}, parent_run_id)

        # Save the result returned by the tool.
        def on_tool_end(self, output, *, run_id, parent_run_id=None, **kwargs):
            value = output.model_dump(mode="json") if hasattr(output, "model_dump") else output
            self.emit("tool_output", run_id, value, parent_run_id)

        # Record a failed tool call so its missing result remains visible.
        def on_tool_error(self, error, *, run_id, parent_run_id=None, **kwargs):
            self.emit("tool_error", run_id, str(error), parent_run_id)

    register_configure_hook(ContextVar("cryptoapi_trace", default=None), True,  handle_class=StageTrace, env_var="SCIP_STAGE_TRACE")


# Export native stage outputs and provenance from the checkpoint database.
def export_checkpoints(directory):
    database = directory / "state/vvaharness.db"
    if not database.exists():
        return

    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        exists = connection.execute("SELECT name FROM sqlite_master WHERE name='checkpoints'").fetchone()
        if not exists:
            return

        for step, payload in connection.execute("SELECT step, payload FROM checkpoints"):
            if re.fullmatch(r"s[0-9]+(?:_prov)?", step):
                stage = step.removesuffix("_prov")
                folder = directory / "stages" / stage
                folder.mkdir(parents=True, exist_ok=True)
                name = "provenance.json" if step.endswith("_prov") else "output.json"
                write_json(folder / name, json.loads(payload))


# Run VVAH through S9 and export available checkpoints when the worker exits.
def worker(directory):
    install_model_logging(directory)
    from vvaharness.cli import main as vvah_main

    try:
        return vvah_main(["--log-level", "debug", "--log-file", str(directory / "diagnostics.jsonl"),
                          "scan", "--repo", str(directory / "source"), "--config", str(directory / "config.yaml"),
                          "--stop-after", "s9"])
    finally:
        export_checkpoints(directory)


# Prepare one isolated Java file, run its worker, and save logs and completion status.
def scan(case, dataset, harness, session, dry_run):
    directory = session / case.stem
    directory.mkdir()
    source = directory / "source"
    before = {}
    relative = case.relative_to(dataset)
    destination = source / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    content = case.read_bytes()
    destination.write_bytes(content)
    before[str(relative)] = hashlib.sha256(content).hexdigest()

    (directory / "config.yaml").write_text(yaml.safe_dump(profile(harness), sort_keys=False), encoding="utf-8")
    upstream = dataset / ".upstream.json"
    revisions = harness.parents[1] / "configs/upstream-revisions.json"
    harness_revision = json.loads(revisions.read_text()).get("harness", {}).get("commit") if revisions.exists() else None
    revision_file = MODEL_DIR / "MODEL_REVISION.txt"
    write_json(directory / "input.json", {
        "case": str(case.relative_to(dataset)), "source_sha256": before,
        "dataset": json.loads(upstream.read_text()) if upstream.exists() else {"commit": "unavailable"},
        "harness_commit": harness_revision, "model": MODEL, "model_dir": str(MODEL_DIR),
        "model_revision": revision_file.read_text().strip() if revision_file.exists() else None,
        "runner_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "base_url": BASE_URL, "context_limit": 262144, "max_output_tokens": OUTPUT_TOKENS,
        "native_thinking_requested": False, "thinking_control": "server default in serve_qwen_3.5-9b.sh; not remotely verified",
        "protocol": "VVAH detection through S9; exactly one Java file, no helpers; original names/comments retained; labels not copied",
    })
    command = [sys.executable, str(Path(__file__).resolve()), "--worker", str(directory)]
    write_json(directory / "command.json", command)
    if dry_run:
        write_json(directory / "status.json", {"status": "prepared_only", "model_requests": 0})
        print(f"[{case.stem}] Prepared {len(before)} source file(s): {directory}", flush=True)
        return 0

    env = dict(os.environ, PYTHONDONTWRITEBYTECODE="1", PYTHONUNBUFFERED="1", NO_PROXY="127.0.0.1,localhost",
               VVAHARNESS_STATE_DIR=str(directory / "state"), VVAHARNESS_TRANSCRIPT_DIR=str(directory / "transcripts"),
               VVAHARNESS_NO_LOCAL_CONFIG="1", SCIP_STAGE_TRACE="1", LANGCHAIN_TRACING_V2="false", LANGCHAIN_TRACING="false",
               LANGSMITH_TRACING="false", PYTHONPATH=str(harness), OPENAI_API_KEY="EMPTY", OPENAI_BASE_URL=BASE_URL)
    started = time.monotonic()
    print(f"[{case.stem}] Starting VVAH; {directory}", flush=True)
    code = 1
    interrupted = False
    current_stage = "preflight"
    with (directory / "scan.log").open("x", encoding="utf-8") as log:
        process = subprocess.Popen(command, cwd=directory, env=env, stdout=subprocess.PIPE,
                                   stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
        try:
            for line in process.stdout:
                log.write(line)
                log.flush()
                event = re.search(r"\[progress\]\s+stage-(?:start|note|done)\s+(s[0-9]+)", line)
                if event:
                    current_stage = event[1]

                stage_folder = directory / "stages" / current_stage
                stage_folder.mkdir(parents=True, exist_ok=True)
                with (stage_folder / "progress.log").open("a", encoding="utf-8") as stage_log:
                    stage_log.write(line)

                print(f"[{case.stem}] {line}", end="", flush=True)

            code = process.wait()
        except KeyboardInterrupt:
            interrupted = True
            os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait()

            code = 130
        finally:
            process.stdout.close()

    after = {str(path.relative_to(source)): hashlib.sha256(path.read_bytes()).hexdigest()
             for path in source.rglob("*.java")}
    report = source / "security-scan/findings.json"
    write_json(directory / "status.json", {
        "status": "interrupted" if interrupted else "finished" if code == 0 else "failed",
        "exit_code": code, "elapsed_seconds": round(time.monotonic() - started, 3),
        "source_unchanged": before == after, "final_report": str(report) if report.exists() else None,
        "degraded": json.loads(report.read_text()).get("degraded") if report.exists() else None,
        "note": "finished records process completion; inspect stage errors and native report for coverage",
    })
    print(f"[{case.stem}] Exit {code}; logs: {directory}", flush=True)
    if interrupted:
        raise KeyboardInterrupt

    return code if before == after else 1


# Select inputs from CLI options and process them sequentially in a new run session.
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, default=ROOT / "datasets/CryptoAPI-Bench")
    parser.add_argument("--harness", type=Path, default=ROOT / "harnesses/visa-vulnerability-agentic-harness")
    parser.add_argument("--output", type=Path, default=ROOT / "runs/cryptoapi-bench")
    parser.add_argument("--case", action="append", help="Exact Java class name, repeatable; otherwise all cases")
    parser.add_argument("--limit", type=int, help="Maximum number of selected cases")
    parser.add_argument("--list", action="store_true", help="List source-derived cases without running VVAH")
    parser.add_argument("--dry-run", action="store_true", help="Prepare source/config only; make no model requests")
    parser.add_argument("--worker", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.worker:
        return worker(args.worker.resolve())

    dataset = args.dataset.resolve()
    harness = args.harness.resolve()
    cases = input_files(dataset)
    if args.case:
        wanted = set(args.case)
        missing = wanted - {path.stem for path in cases}
        if missing:
            parser.error(f"Unknown cases: {sorted(missing)}")

        cases = [path for path in cases if path.stem in wanted]

    if args.limit is not None:
        if args.limit < 1:
            parser.error("--limit must be positive")

        cases = cases[:args.limit]

    if args.list:
        print("\n".join(path.stem for path in cases))
        print(f"{len(cases)} input files; each scan receives exactly one file")
        return 0

    session = args.output.resolve() / datetime.datetime.now(ZoneInfo("America/New_York")).strftime("%Y-%m-%d_%H-%M-%S_%f_%Z")
    session.mkdir(parents=True)
    print(f"Selected {len(cases)} case(s); session: {session}", flush=True)
    total = len(cases)
    processed = 0
    failed = 0
    action = "Preparing" if args.dry_run else "Starting"
    completed_action = "Prepared" if args.dry_run else "Processed"
    try:
        for position, case in enumerate(cases, start=1):
            print(f"[{position}/{total}] {action} {case.name}; {processed} already processed", flush=True)
            failed += bool(scan(case, dataset, harness, session, args.dry_run))
            processed += 1
            print(f"[progress] {completed_action} {processed}/{total}; failed: {failed}; remaining: {total - processed}", flush=True)

    except KeyboardInterrupt:
        print(f"Interrupted after {processed}/{total} processed; failed: {failed}. Logs preserved; rerun with --case to retry the interrupted file.", flush=True)
        return 130

    print(f"{completed_action} {processed}/{total} input file(s); failed processes/integrity checks: {failed}; session: {session}", flush=True)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
