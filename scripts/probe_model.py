#!/usr/bin/env python3
"""Plain chat, automatic tool call, and genuine tool replay (no invented calls)."""

import argparse
import json
import pathlib
import secrets
import sys
import time

import yaml
from openai import OpenAI
from vvaharness.backends.harness.deepagents.limits import (
    MODEL_MAX_RETRIES,
    MODEL_TIMEOUT_SECONDS,
)
from request_guard import DEFAULT_SETTINGS, load_settings


def probe(out, settings=None):
    settings = settings or DEFAULT_SETTINGS
    profile = (
        pathlib.Path(__file__).resolve().parents[1]
        / "harnesses/visa-vulnerability-agentic-harness/vvaharness/config/profiles/default.yaml"
    )
    output = yaml.safe_load(profile.read_text())["step1"]["auto_exclude_max_tokens"]
    c = OpenAI(
        base_url="http://127.0.0.1:8003/v1",
        api_key="EMPTY",
        max_retries=MODEL_MAX_RETRIES,
        timeout=MODEL_TIMEOUT_SECONDS,
    )
    result = {"tool_roundtrip": False, "started": time.time()}
    try:
        result["models"] = c.models.list().model_dump()
        served = next(
            (model for model in result["models"]["data"] if model["id"] == settings["model_name"]),
            None,
        )
        if served is None:
            raise RuntimeError("Configured model ID is absent from /v1/models")

        server_context = served.get("max_model_len")
        if server_context is not None and server_context < settings["context_limit"]:
            raise RuntimeError(
                f"Server context {server_context} is smaller than configured {settings['context_limit']}"
            )

        result["chat"] = c.chat.completions.create(
            model=settings["model_name"],
            messages=[{"role": "user", "content": "Reply with OK."}],
            max_tokens=output,
        ).model_dump()
        messages = [
            {
                "role": "user",
                "content": "Call read_marker with no arguments to read a secret marker; then return the exact marker received from the tool.",
            }
        ]
        tools = [
            {
                "type": "function",
                "function": {
                    "name": "read_marker",
                    "description": "Reads the secret marker.",
                    "parameters": {"type": "object", "properties": {}, "required": []},
                },
            }
        ]
        r = c.chat.completions.create(
            model=settings["model_name"],
            messages=messages,
            tools=tools,
            tool_choice="auto",
            max_tokens=output,
        )
        result["tool_request"] = r.model_dump()
        m = r.choices[0].message
        if not m.tool_calls:
            raise RuntimeError("Model returned no actual tool_calls")

        messages.append(m.model_dump(exclude_none=True))
        nonce = secrets.token_hex(8)
        for call in m.tool_calls:
            if (
                call.function.name != "read_marker"
                or json.loads(call.function.arguments) != {}
            ):
                raise RuntimeError("Invalid model-produced tool request")

            messages.append({"role": "tool", "tool_call_id": call.id, "content": nonce})
        r = c.chat.completions.create(
            model=settings["model_name"],
            messages=messages,
            tools=tools,
            tool_choice="auto",
            max_tokens=output,
        )
        result["replay"] = r.model_dump()
        result["tool_roundtrip"] = nonce in (r.choices[0].message.content or "")
        if not result["tool_roundtrip"]:
            raise RuntimeError("Actual tool result not echoed")

    except Exception as e:
        result["error"] = str(e)
    result["elapsed_seconds"] = time.time() - result["started"]
    pathlib.Path(out).write_text(json.dumps(result, indent=2) + "\n")
    return result["tool_roundtrip"]


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("output")
    p.add_argument("--model-config")
    a = p.parse_args()
    settings = load_settings(a.model_config) if a.model_config else None
    sys.exit(0 if probe(a.output, settings) else 1)

