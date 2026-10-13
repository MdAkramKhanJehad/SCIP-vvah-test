#!/usr/bin/env python3
import importlib.util
import io
import json
import pathlib
import shutil
import sys
import tempfile
import unittest
import yaml
from contextlib import redirect_stdout
from unittest import mock

import run_baseline
import probe_model
from convert_findings import convert, endpoint
from evaluate_run import ROOT, evaluate
from request_guard import DEFAULT_SETTINGS, load_settings, template_messages, validate
from run_baseline import command, failure_reason, model_profile, upstream_changes
from vvaharness.config import load


class Boundaries(unittest.TestCase):
    def test_controller_records_upstream_limits_and_uses_native_preflight(self):
        settings = load_settings(ROOT / "configs/qwen38-27b-fp8-256k.json")
        target = {"target_id": "fixture", "repo_url": "https://example.com/repo", "commit": "a" * 40}
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            (workspace / "configs").mkdir()
            for name in ("baseline.local.yaml", "harness-requirements.lock.txt", "upstream-revisions.json"):
                shutil.copy2(ROOT / "configs" / name, workspace / "configs" / name)
            source = workspace / "targets" / "fixture"
            source.mkdir(parents=True)
            (source / "source.py").write_text("value = 1\n")

            def complete_command(args, cwd, env, log):
                if args[1] == "scan":
                    output = cwd / "scan-source" / "security-scan"
                    output.mkdir()
                    (output / "findings.json").write_text(json.dumps({"schema_version": "1.0", "findings": []}))

                return 0

            with mock.patch.object(run_baseline, "ROOT", workspace), \
                    mock.patch.object(run_baseline, "command", side_effect=complete_command) as execute, \
                    mock.patch.object(run_baseline.subprocess, "Popen") as launch, \
                    mock.patch.object(run_baseline.socket, "create_connection"), \
                    mock.patch.object(run_baseline.os, "killpg"), \
                    mock.patch.object(run_baseline, "upstream_changes", return_value={"harness": [], "dataset": []}), \
                    mock.patch.object(run_baseline, "evaluate"), redirect_stdout(io.StringIO()):
                launch.return_value.poll.return_value = None
                outcome = run_baseline.run_target(target, settings)
                status = next((workspace / "runs").glob("*/status.json"))
                self.assertEqual(outcome, "completed", status.read_text())

            self.assertEqual([call.args[0][1] for call in execute.call_args_list], ["estimate", "scan"])
            self.assertTrue(all(len(call.args) == 4 for call in execute.call_args_list))
            run = next((workspace / "runs").iterdir())
            limits = json.loads((run / "limits.json").read_text())
            self.assertIsNone(limits["scan_wall_seconds"])
            self.assertFalse(limits["request_serialization"])
            self.assertEqual(limits["stage_limits"]["step2"]["max_tokens"], 64000)
            self.assertEqual(limits["stage_limits"]["step4"]["parallel"], 12)
            self.assertEqual(limits["stage_limits"]["step6_verify"]["parallel"], 7)
            self.assertTrue(json.loads((run / "status.json").read_text())["canonical_source_unchanged"])

    def test_qwen_profile_keeps_upstream_source_packing(self):
        settings = load_settings(ROOT / "configs/qwen38-27b-fp8-256k.json")
        self.assertEqual(settings["context_limit"], 262144)
        self.assertNotIn("output_limit", settings)
        with tempfile.TemporaryDirectory() as directory:
            effective = load(model_profile(pathlib.Path(directory), settings))
            self.assertEqual(effective.models.threatmodel.id, "qwen38-27b-fp8")
            self.assertEqual(effective.models.verify.id, "qwen38-27b-fp8")
            self.assertTrue(effective.step4.inline_source)
            self.assertTrue(effective.step6_verify.inline_source)
            self.assertEqual(effective.step2.max_inventory_files, 1200)

    def test_probe_rejects_smaller_server_context_before_inference(self):
        settings = load_settings(ROOT / "configs/qwen38-27b-fp8-256k.json")
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(probe_model, "OpenAI") as client:
            client.return_value.models.list.return_value.model_dump.return_value = {
                "data": [{"id": settings["model_name"], "max_model_len": 131072}]
            }
            output = pathlib.Path(directory) / "compatibility.json"
            self.assertFalse(probe_model.probe(output, settings))
            self.assertIn("smaller than configured", json.loads(output.read_text())["error"])
            client.return_value.chat.completions.create.assert_not_called()

    def test_text_blocks_and_tool_replay_accounting(self):
        messages = [
            {"role": "system", "content": [{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]},
            {"role": "assistant", "content": None, "reasoning": "model reasoning", "tool_calls": [
                {"type": "function", "function": {"name": "Read", "arguments": '{"path":"x.py"}'}}
            ]},
        ]
        normalized = template_messages(messages)
        self.assertEqual(normalized[0]["content"], "a\nb")
        self.assertEqual(normalized[1]["content"], "")
        self.assertEqual(normalized[1]["reasoning_content"], "model reasoning")
        self.assertNotIn("reasoning_content", messages[1])
        self.assertEqual(normalized[1]["tool_calls"][0]["function"]["arguments"], {"path": "x.py"})
        self.assertIsInstance(messages[0]["content"], list)
        self.assertIsInstance(messages[1]["tool_calls"][0]["function"]["arguments"], str)

    def test_context_profile_preserves_source_access(self):
        baseline = (ROOT / "configs/baseline.local.yaml").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            profile = model_profile(
                pathlib.Path(directory), DEFAULT_SETTINGS, ROOT / "configs/context32k.local.yaml"
            )
            config = load(profile)
            self.assertFalse(config.step4.inline_source)
            self.assertFalse(config.step6_verify.inline_source)
            self.assertIn("Read", config.step6_verify.allowed_tools)
            self.assertTrue(config.step2.graph_tools)
            self.assertEqual(config.step2.max_threats, 50)
            self.assertEqual(config.step2.max_graph_files, 220)
        self.assertEqual((ROOT / "configs/baseline.local.yaml").read_bytes(), baseline)

    def test_live_stage_updates_preserve_full_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "scan.log"
            console = io.StringIO()
            script = (
                "print('[progress] stage-start s2'); "
                "print('unrelated diagnostic'); "
                "print('[progress] stage-done s2 outcome=completed')"
            )
            with redirect_stdout(console):
                code = command([sys.executable, "-c", script], directory, {}, log)
            self.assertEqual(code, 0)
            self.assertIn("stage-start s2", console.getvalue())
            self.assertIn("stage-done s2", console.getvalue())
            self.assertNotIn("unrelated diagnostic", console.getvalue())
            self.assertIn("unrelated diagnostic", log.read_text())

    def test_heartbeat_wait_does_not_terminate_scan(self):
        with tempfile.TemporaryDirectory() as directory:
            log = pathlib.Path(directory) / "scan.log"
            process = mock.Mock()
            process.stdout = io.StringIO("[progress] stage-start s2\n")
            process.wait.side_effect = [run_baseline.subprocess.TimeoutExpired("scan", 30), 0]
            with mock.patch.object(run_baseline.subprocess, "Popen", return_value=process), \
                    mock.patch.object(run_baseline.os, "killpg") as kill, redirect_stdout(io.StringIO()):
                self.assertEqual(command(["scan"], directory, {}, log), 0)
            kill.assert_not_called()
            self.assertEqual(process.wait.call_count, 2)

    def test_runner_after_detachment_without_freeze_file(self):
        self.assertFalse((ROOT / "configs/frozen-baseline.json").exists())
        with tempfile.TemporaryDirectory() as directory:
            workspace = pathlib.Path(directory)
            (workspace / "configs").mkdir()
            (workspace / "datasets").mkdir()
            for name in ("baseline.local.yaml", "upstream-revisions.json"):
                shutil.copy2(ROOT / "configs" / name, workspace / "configs" / name)
            shutil.copy2(ROOT / "datasets/manifest.json", workspace / "datasets/manifest.json")
            manifest = json.loads((workspace / "datasets/manifest.json").read_text())
            (workspace / "targets" / manifest["targets"][0]["target_id"]).mkdir(parents=True)
            with mock.patch("sys.argv", ["run_baseline.py", "--limit", "1"]), \
                    mock.patch.object(run_baseline, "ROOT", workspace), \
                    mock.patch.object(run_baseline, "upstream_changes", return_value={"harness": [], "dataset": []}), \
                    mock.patch.object(run_baseline, "run_target", return_value="completed") as scan:
                self.assertEqual(run_baseline.main(), 0)
                scan.assert_called_once()
                self.assertIsNone(scan.call_args.args[1])

    def test_detached_upstream_integrity(self):
        self.assertFalse((ROOT / "datasets/VulnGym/.git").exists())
        self.assertFalse(
            (ROOT / "harnesses/visa-vulnerability-agentic-harness/.git").exists()
        )
        self.assertEqual(upstream_changes(), {"harness": [], "dataset": []})

    def test_other_local_model_configuration(self):
        settings = dict(
            DEFAULT_SETTINGS,
            model_name="another-local-model",
            context_limit=8192,
        )
        with tempfile.TemporaryDirectory() as directory:
            run = pathlib.Path(directory)
            settings["model_dir"] = directory
            settings["tokenizer_python"] = sys.executable
            config = run / "model.json"
            config.write_text(json.dumps(settings))
            self.assertEqual(load_settings(config), settings)
            profile = model_profile(run, settings)
            effective = load(profile)
            self.assertEqual(effective.models.deepdive.id, "another-local-model")
            self.assertIsNone(getattr(effective.models.verify, "max_tokens", None))
            self.assertEqual(effective.step6_verify.max_tokens, 32000)
            self.assertFalse(effective.step_remediate.enabled)
            settings["base_url"] = "https://api.example.com/v1"
            config.write_text(json.dumps(settings))
            with self.assertRaisesRegex(ValueError, "Only a local HTTP"):
                load_settings(config)

    def test_context_accounting_preserves_upstream_allowances(self):
        class Counter:
            count = 20768

            def apply_chat_template(self, messages, **kwargs):
                self.kwargs = kwargs
                return [1] * self.count

        counter = Counter()
        request = {
            "model": "vulnllm-r-7b",
            "messages": [{"role": "system", "content": "system"}],
            "max_tokens": 12000,
        }
        original = json.loads(json.dumps(request))
        self.assertEqual(validate(request, counter), (20768, 12000))
        self.assertEqual(request, original)
        counter.count += 1
        with self.assertRaisesRegex(ValueError, "Context budget exceeded"):
            validate(request, counter)

        counter.count = 10
        request["max_tokens"] = 4097
        self.assertEqual(validate(request, counter), (10, 4097))
        del request["max_tokens"]
        self.assertEqual(validate(request, counter), (10, None))
        self.assertNotIn("max_tokens", request)
        request["model"] = "remote-model"
        with self.assertRaisesRegex(ValueError, "Only the baseline"):
            validate(request, counter)

    def test_config(self):
        c = load(
            ROOT
            / "harnesses/visa-vulnerability-agentic-harness/vvaharness/config/profiles/default.yaml"
        )
        for key in (
            "autoexclude",
            "preprocess",
            "threatmodel",
            "decompose",
            "deepdive",
            "verify",
            "dedup",
            "chain",
            "remediate",
        ):
            m = getattr(c.models, key)
            self.assertEqual(
                (m.id, m.via, m.provider, m.use_responses_api),
                ("vulnllm-r-7b", "deepagents", "openai", False),
            )
        native = yaml.safe_load(run_baseline.PROFILE.read_text())
        for stage, values in native.items():
            if stage.startswith("step") and isinstance(values, dict) and stage not in {
                "step_remediate", "step_validate", "step6_exploit_verification"
            }:
                for key, value in values.items():
                    self.assertEqual(c[stage][key], value, f"{stage}.{key}")

        self.assertEqual(c.step4.parallel, 12)
        self.assertEqual(c.step6_verify.parallel, 7)
        self.assertEqual(c.step2.max_tokens, 64000)
        self.assertEqual(c.step8.prompt_token_budget, 100000)
        self.assertFalse(c.step_remediate.enabled)
        self.assertFalse(c.step_validate.enabled)
        self.assertFalse(c.step6_exploit_verification.enabled)

    def test_no_invented_locations(self):
        t = {"repo_url": "https://example.com/repo", "commit": "a" * 40}
        raw = {
            "schema_version": "1.0",
            "findings": [
                {
                    "finding": {
                        "file": "sink.py",
                        "line_start": 99,
                        "source_ref": None,
                        "sink_ref": "sink.py:99",
                    }
                }
            ],
        }
        rows, errors = convert(raw, t)
        self.assertEqual(rows, [])
        self.assertTrue(errors[0]["missing_evidence"])
        raw["findings"][0]["finding"]["source_ref"] = "src.py:3"
        rows, errors = convert(raw, t)
        self.assertEqual(rows[0]["entry_point"], {"file": "src.py", "line": 3})
        self.assertEqual(errors, [])
        raw["findings"][0]["finding"]["backfilled_refs"] = ["source_ref"]
        self.assertEqual(convert(raw, t)[0], [])

    def test_paths_and_schema(self):
        for ref in ("../secret:1", "/abs:1", "x.py:0", "x.py:1-3", "x.py:1 -> y.py:2"):
            with self.assertRaises(ValueError):
                endpoint(ref)
        with self.assertRaises(ValueError):
            convert({"findings": []}, {})

    def test_failure_has_no_recall(self):
        with tempfile.TemporaryDirectory() as d:
            run = pathlib.Path(d)
            (run / "status.json").write_text(json.dumps({"status": "failed"}))
            selected = json.loads((ROOT / "datasets/manifest.json").read_text())[
                "targets"
            ][0]
            target = {key: selected[key] for key in ("repo_url", "commit")}
            (run / "target.json").write_text(json.dumps(target))
            (run / "converted.jsonl").touch()
            result = evaluate(run)
            self.assertIsNone(result["official_result"])
            self.assertEqual(result["selected_entries"], 1)

    def test_official_direction_and_tolerance(self):
        spec = importlib.util.spec_from_file_location(
            "official", ROOT / "datasets/VulnGym/examples/evaluate.py"
        )
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        e = {
            "entry_point": {"file": "a.py", "line": 10},
            "critical_operation": {"file": "b.py", "line": 20},
        }
        f = {
            "entry_point": {"file": "./a.py", "line": 15},
            "critical_operation": {"file": "b.py", "line": 25},
        }
        self.assertTrue(m.finding_matches_entry(f, e, 5))
        f["entry_point"]["line"] = 16
        self.assertFalse(m.finding_matches_entry(f, e, 5))
        self.assertFalse(
            m.finding_matches_entry(
                {
                    "entry_point": e["critical_operation"],
                    "critical_operation": e["entry_point"],
                },
                e,
                5,
            )
        )


if __name__ == "__main__":
    unittest.main()

