#!/usr/bin/env python3
"""Local transport and token trace; preserve VVAH request budgets and concurrency."""

import argparse
import copy
import json
import os
import pathlib
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = pathlib.Path(__file__).resolve().parents[1]
TRACE_LOCK = threading.Lock()
TOKENIZER = None
OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))
DEFAULT_SETTINGS = {
    "model_name": "vulnllm-r-7b",
    "model_dir": "/scratch/mkhan04/local_models/vulnLLM-R-7B",
    "base_url": "http://127.0.0.1:8002/v1",
    "tokenizer_python": "/scratch/mkhan04/qwen38-vllm/vllm-env/bin/python",
    "context_limit": 32768,
}
SETTINGS = DEFAULT_SETTINGS


def template_messages(messages):
    """Match vLLM's string-content preprocessing without changing the API payload."""
    normalized = copy.deepcopy(messages)
    for message in normalized:
        if message.get("role") == "assistant":
            reasoning = message.get("reasoning")
            if reasoning is None:
                reasoning = message.get("reasoning_content")

            if reasoning is not None:
                message["reasoning_content"] = reasoning

        content = message.get("content")
        if content is None:
            message["content"] = ""
        elif isinstance(content, list):
            if any(part.get("type") != "text" for part in content):
                raise ValueError("The local text-model guard supports text content only")

            message["content"] = "\n".join(part.get("text", "") for part in content)

        for call in message.get("tool_calls") or []:
            function = call.get("function", {})
            arguments = function.get("arguments")
            if isinstance(arguments, str):
                function["arguments"] = json.loads(arguments)

    return normalized


def load_settings(path):
    settings = json.loads(pathlib.Path(path).read_text())
    if set(settings) != set(DEFAULT_SETTINGS):
        raise ValueError(
            "Model configuration must contain exactly: " + ", ".join(DEFAULT_SETTINGS)
        )

    url = urllib.parse.urlsplit(settings["base_url"])
    if (
        url.scheme != "http"
        or url.hostname not in ("127.0.0.1", "localhost", "::1")
        or url.username
        or url.password
        or url.query
        or url.fragment
        or url.path.rstrip("/") != "/v1"
    ):
        raise ValueError(
            "Only a local HTTP /v1 endpoint without URL credentials is supported"
        )

    if not isinstance(settings["model_name"], str) or not settings["model_name"]:
        raise ValueError("A nonempty served model name is required")

    if (
        not isinstance(settings["context_limit"], int)
        or settings["context_limit"] < 1
    ):
        raise ValueError("A positive model context limit is required")

    if (
        not pathlib.Path(settings["model_dir"]).is_dir()
        or not pathlib.Path(settings["tokenizer_python"]).is_file()
    ):
        raise ValueError("Existing model directory and tokenizer Python are required")

    return settings


def validate(data, tokenizer, settings=None):
    settings = settings or DEFAULT_SETTINGS
    if data.get("model") != settings["model_name"]:
        raise ValueError("Only the baseline/configured local model is permitted")

    output = data.get("max_completion_tokens", data.get("max_tokens"))
    if output is not None and (not isinstance(output, int) or output < 1):
        raise ValueError("Requested output allowance must be a positive integer")

    template_kwargs = dict(data.get("chat_template_kwargs") or {})
    if data.get("reasoning_effort") is not None:
        template_kwargs.setdefault("reasoning_effort", data["reasoning_effort"])
        template_kwargs.setdefault("enable_thinking", data["reasoning_effort"] != "none")

    tokens = tokenizer.apply_chat_template(
        template_messages(data["messages"]),
        tools=data.get("tools"),
        tokenize=True,
        add_generation_prompt=True,
        return_dict=False,
        **template_kwargs,
    )
    if not isinstance(tokens, list) or any(not isinstance(t, int) for t in tokens):
        raise ValueError("Tokenizer did not return a flat token list")

    if len(tokens) + (output or 0) > settings["context_limit"]:
        raise ValueError(
            f"Context budget exceeded: {len(tokens)} input + {output} output > {settings['context_limit']}; no source truncated"
        )

    return len(tokens), output


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def handle_request(self):
        if self.path not in ("/v1/models", "/v1/chat/completions"):
            self.send_error(404)
            return

        started = time.monotonic()
        record = {"path": self.path, "time": time.time()}
        response = None
        headers_sent = False
        parts = []
        try:
            body = None
            if self.command == "POST":
                body = self.rfile.read(int(self.headers.get("Content-Length", 0)))
                data = json.loads(body)
                record["request"] = data
                count, output = validate(data, TOKENIZER, SETTINGS)
                body = json.dumps(data).encode()
                record.update(input_tokens=count, output_allowance=output)

            request = urllib.request.Request(
                SETTINGS["base_url"].rstrip("/") + self.path.removeprefix("/v1"),
                data=body,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": "Bearer "
                    + os.environ.get("SCIP_LOCAL_API_KEY", "EMPTY"),
                },
                method=self.command,
            )
            try:
                response = OPENER.open(request, timeout=None)
            except urllib.error.HTTPError as e:
                response = e
            record["status"] = response.code
            self.send_response(response.code)
            self.send_header(
                "Content-Type",
                response.headers.get("Content-Type", "application/json"),
            )
            self.end_headers()
            headers_sent = True
            while True:
                chunk = response.read1(65536)
                if not chunk:
                    break

                parts.append(chunk.decode(errors="replace"))
                self.wfile.write(chunk)
                self.wfile.flush()
            record["response"] = "".join(parts)
        except Exception as e:
            status = 504 if isinstance(e, TimeoutError) else 400
            record.update(status=status, error=str(e))
            payload = json.dumps(
                {
                    "error": {
                        "message": str(e),
                        "type": "baseline_guard_error",
                        "code": "budget_or_transport",
                    }
                }
            ).encode()
            try:
                if not headers_sent:
                    self.send_response(status)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(payload)
                else:
                    self.close_connection = True
                    record["partial_response"] = "".join(parts)

            except OSError:
                pass
        finally:
            if response is not None:
                response.close()

            record["elapsed_seconds"] = time.monotonic() - started
            with TRACE_LOCK:
                with open(self.server.trace, "a") as f:
                    f.write(json.dumps(record) + "\n")

    do_GET = handle_request
    do_POST = handle_request


if __name__ == "__main__":
    from transformers import AutoTokenizer

    p = argparse.ArgumentParser()
    p.add_argument("--trace", required=True)
    p.add_argument("--model-config")
    a = p.parse_args()
    SETTINGS = load_settings(a.model_config) if a.model_config else DEFAULT_SETTINGS
    TOKENIZER = AutoTokenizer.from_pretrained(
        SETTINGS["model_dir"], local_files_only=True
    )
    server = ThreadingHTTPServer(("127.0.0.1", 8003), Handler)
    server.trace = a.trace
    server.serve_forever()

