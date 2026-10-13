#!/usr/bin/env python3
"""Real-tokenizer network boundary check; does not generate large model completions."""

import datetime
import json
import os
import pathlib
import subprocess
import socket
import time
import urllib.error
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    run = (
        ROOT
        / "runs"
        / (
            "guard-boundaries-"
            + datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        )
    )
    run.mkdir(parents=True)
    log = (run / "guard.log").open("w")
    env = dict(os.environ, HF_HUB_OFFLINE="1", TRANSFORMERS_OFFLINE="1")
    proc = subprocess.Popen(
        [
            "/scratch/mkhan04/qwen38-vllm/vllm-env/bin/python",
            str(ROOT / "scripts/request_guard.py"),
            "--trace",
            str(run / "trace.jsonl"),
        ],
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    results = []
    try:
        for _ in range(60):
            if proc.poll() is not None:
                raise RuntimeError("Guard start failed")

            try:
                socket.create_connection(("127.0.0.1", 8003), timeout=2).close()
                break
            except Exception:
                time.sleep(0.5)
        else:
            raise RuntimeError("Readiness timeout")
        for name, data, expected in [
            (
                "output_exceeds_model_context",
                {
                    "model": "vulnllm-r-7b",
                    "messages": [{"role": "user", "content": "OK"}],
                    "max_tokens": 32769,
                },
                "Context budget exceeded",
            ),
            (
                "oversized_context",
                {
                    "model": "vulnllm-r-7b",
                    "messages": [{"role": "user", "content": "x " * 40000}],
                    "max_tokens": 4096,
                },
                "Context budget exceeded",
            ),
            (
                "remote_model_refused",
                {"model": "remote", "messages": [{"role": "user", "content": "OK"}]},
                "Only the baseline",
            ),
        ]:
            request = urllib.request.Request(
                "http://127.0.0.1:8003/v1/chat/completions",
                data=json.dumps(data).encode(),
                headers={"Content-Type": "application/json"},
            )
            try:
                opener.open(request, timeout=15)
                raise AssertionError("Invalid request accepted")
            except urllib.error.HTTPError as e:
                body = json.loads(e.read())
                assert e.code == 400 and expected in body["error"]["message"]
                results.append({"test": name, "passed": True, "error": body})
    finally:
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=5)

        log.close()
        (run / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(run)


if __name__ == "__main__":
    main()

