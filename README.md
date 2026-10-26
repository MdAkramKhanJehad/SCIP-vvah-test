# VVAH on CryptoAPI-Bench

Run the vendored Visa Vulnerability Agentic Harness with the existing local Qwen 3.5 9B model. The active workflow uses only three scripts. No ground-truth matching is performed yet.

## 1. Download the dataset

```bash
cd /home/spl/akram/SCIP-vvah-test
.venv/bin/python scripts/download_cryptoapi_bench.py
```

This creates `datasets/CryptoAPI-Bench/`, pinned by default to commit `e6b6b50fef6970151300c1ac2de62e188ba6de19`. `.upstream.json` records the source URL and exact commit. The download contains the upstream spreadsheet for later evaluation, but retains no Git history. An existing dataset is not overwritten.

## 2. Serve Qwen 3.5 9B

On the machine with the GPU:

```bash
bash scripts/serve_qwen_3.5-9b.sh
```

This uses the weights at `/home/spl/akram/local_models/qwen3.5-9b` and the existing `qwen38-vllm/vllm-env`. It follows `/home/spl/akram/local_models/run_qwen3.5-9b.sh`: BF16, port **8005**, model name **qwen35-9b**, context **262144**, GPU memory utilization **0.60**, one sequence, batched-token budget **8192**, prefix caching, capture size **1**, and the same reasoning/tool parsers. The added `--default-chat-template-kwargs '{"enable_thinking": false}'` disables native thinking. The environment and weights are not modified. If port 8005 is already occupied by the older launcher, stop that server in its owning terminal before starting this script; an existing process does not inherit the new no-thinking flag.

## 3. Run one file first

In another terminal on the same machine:

```bash
cd /home/spl/akram/SCIP-vvah-test
.venv/bin/python -u scripts/run_cryptoapi_bench.py --limit 1
```

Select a particular file by its Java class name:

```bash
.venv/bin/python -u scripts/run_cryptoapi_bench.py --case BrokenCryptoABMCCase1
```

List input files, or prepare one without calling a model:

```bash
.venv/bin/python scripts/run_cryptoapi_bench.py --list
.venv/bin/python scripts/run_cryptoapi_bench.py --limit 1 --dry-run
```

Run every Java file sequentially:

```bash
.venv/bin/python -u scripts/run_cryptoapi_bench.py
```

The snapshot has **203 Java source files**. Each VVAH invocation receives **exactly one file**, copied with its original relative path and contents. Helper classes are separate inputs; they are not bundled with callers. Consequently this protocol does not supply the cross-file context of upstream multi-class benchmark cases. File names such as `Corrected` and original source comments are retained; this is not a blinded benchmark.

The runner uses VVAH's documented `scan --repo ... --stop-after s9` path, with read-only DeepAgents detection tools. Every model role points to `http://127.0.0.1:8005/v1`; remote model fallbacks, exploit verification, remediation, report uploads, and external annotation injection are disabled. S4 and S6 each use one worker to match the server's one sequence. The runner does not execute the Java samples.

Detection output budgets, including replay budgets, are **131072 tokens**; model roles cap native retry growth at that same allowance. Input plus output must fit within **262144 tokens**. A large allowance is not a guarantee of complete generation: the model can stop early, tools have their own output limits, and native VVAH context packing and finite stage/call budgets still apply. Their failures and native truncation warnings remain visible in the logs. No wrapper wall-clock deadline or automatic whole-scan retry is added.

## Outputs and stage visibility

Every invocation creates a new session in New York time using a readable 24-hour clock:

```text
runs/cryptoapi-bench/YYYY-MM-DD_HH-MM-SS_microseconds_EDT/
  BrokenCryptoABMCCase1/
    input.json                   # selected file, input checksum, dataset/harness/model revisions, budgets
    config.yaml                  # full effective VVAH profile
    command.json                 # exact worker command
    scan.log                     # complete console output, also streamed live
    diagnostics.jsonl            # native VVAH debug records
    status.json                  # exit code, elapsed time, report path, source integrity
    stages/
      preflight/model-events.jsonl
      s0/progress.log
      s0/output.json
      s1/...
      s2/model-events.jsonl
      s2/output.json
      s2/provenance.json
      ...
      s9/...
    transcripts/                 # native agent turns and tool traces
    state/                       # native checkpoint database and graph state
    source/
      src/main/java/.../BrokenCryptoABMCCase1.java
      security-scan/
        findings.json            # final VVAH report, when emitted
        ...                      # native Markdown, SARIF, manifests, and errors
```

`EST` replaces `EDT` when applicable. `model-events.jsonl` records application-level model inputs (system/user/history messages and reported tool schemas/parameters), generated outputs, tool inputs/results, request IDs, phases, and reported usage without clipping text in this logger. These are LangChain callback observations, not raw HTTP packets or the server's rendered token stream. No authentication headers or API secrets are logged. Deterministic stages make no model requests and therefore have no model-event log.

Stage `output.json` files are JSON exports of VVAH's actual SQLite checkpoints, written when the worker exits. The original checkpoint database is also retained. Stages that fail before checkpointing have no output checkpoint; consult their progress, error events, and native error files. A process exit of zero alone does not certify a complete detection result: inspect the native manifest stage outcomes, errors, and `degraded` field. Original dataset sources remain unchanged; VVAH writes reports only in each run's disposable copy.

The runner never reads the spreadsheet, dataset README, or ground-truth labels. Only the selected Java file is placed in the agent's read-only scan inventory. Spreadsheet labels and annotations are not passed as prompts or injected knowledge. Original source comments and descriptive filenames remain visible.

Ctrl+C stops the active worker process group and saves its status. A retry starts a fresh session; it does not overwrite or resume the old run. This minimal runner has no shared multi-server claims or automatic skip queue. Use different explicit `--case` selections if running on multiple machines.

## Ground truth, reserved for later evaluation

`datasets/CryptoAPI-Bench/CryptoAPI-Bench_details.xlsx` has a `Vulnerabilities` worksheet with columns for properties, file(s), code number, vulnerability existence, vulnerability type, method name, line references, and notes. Some rows describe multiple files; some line-reference cells have Excel date formatting/serial values. The spreadsheet and source listing also differ in places. Later evaluation must reconcile those details rather than assume every source file is an independently labeled benchmark case. No matching script or test file is added in this workflow.

Earlier VulnGym datasets, `vulngym-runs/`, `vulngym-targets/`, and their configuration/protocol records are retained as historical research artifacts. Their old runner, evaluation, test, and model-serving scripts have been removed from `scripts/`. The harness source and existing Python/model environments are retained.
