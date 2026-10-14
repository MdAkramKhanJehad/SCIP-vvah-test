# Run VVAH on VulnGym with a local model

Work from `/home/spl/akram/SCIP-vvah-test`. The harness installation is `.venv`
(Python 3.12.0). Existing model files and the serving environment are unchanged.
Harness and dataset source directories have no nested Git repositories.
`configs/upstream-revisions.json` records their commits and source checksums.

| Source | Recorded commit |
| --- | --- |
| VVAH 1.5.0 | `4128e870377850db16cb082115105cc8ee6f1a72` |
| VulnGym | `abfcb1aa0cb4e8719f6550b0a7b41169d7a3843f` |
| VulnLLM-R-7B | `8cd13d7a35f13b187102dba166413d4450836a40` |
| First target: BerriAI/litellm | `24f847b84c947e13b765edaf172f646fd1b06297` |


Model storage is now `/home/spl/akram/local_models`: VulnLLM lives directly in
`vulnLLM-R-7B/`, and the complete Qwen serving tree lives in `qwen38-vllm/`.
The old `/scratch/mkhan04/local_models` and `/scratch/mkhan04/qwen38-vllm`
locations are compatibility symlinks. Keep them while using this unchanged
serving environment: its interpreter links, shebangs and activation files
embed those original paths. The repository's scripts and model JSON settings
use the new physical locations.

The NFS destination does not support the source POSIX ACL metadata. Original
Qwen ACLs were saved in
`/home/spl/akram/local_models/qwen38-vllm.posix-acl-backup.txt`. A 24 KB remnant
of empty `nobody`-owned cache directories could not be deleted and remains at
`/scratch/mkhan04/.qwen38-vllm-relocation-residue`; no model weights remain there.
No model, harness or tests were started during relocation.

## Execution settings

At the user's request, VVAH's shipped `default.yaml` now controls detection
parameters. The local overlay selects the local OpenAI-compatible provider,
turns off incompatible Anthropic cache markers, and disables exploit verification,
remediation, validation and report upload. It does not override output allowances,
replay budgets, parallelism, stage deadlines, model-call counts or prompt budgets.

| Setting | Shipped VVAH value |
| --- | ---: |
| Repository-survey output | 8000 tokens |
| S2 output / deadline | 64000 tokens / 400 seconds |
| S4 output / workers | 64000 tokens / 12 |
| S6 output / workers | 32000 tokens / 7 |
| S8 output / prompt budget | 48000 tokens / 100000 tokens |

The runner has no separate probe/estimate/setup/scan wall limit. The former
`--wall-seconds` option and `configs/limits.json` were removed. Its 30-second
heartbeat only reports elapsed time and the current stage; it does not stop a
scan. VVAH retains its own deadlines, retries and model-call limits. On a failed
scan the runner follows upstream instructions: setup, then one identical retry.

VVAH performs its native model connectivity and agent-tool preflight. The
standalone `probe_model.py` is an optional diagnostic, outside the scan workflow;
it derives its output allowance and client retry/timeout defaults from upstream.
It has no wrapper temperature or seed override.

The model server still controls its context window and active sequence capacity.
The proxy on port 8003 counts complete requests and records traces, with no
output cap, request serialization or additional upstream socket timeout. It
forwards VVAH's requested output allowance unchanged and never adds one when
absent. Input plus requested output must fit the configured model context.
Incompatible upstream allowances produce an explicit failure; the proxy does
not silently shrink budgets, truncate source or extend server context.

## Qwen3.8-27B-FP8

Terminal 1:

```bash
cd /home/spl/akram/SCIP-vvah-test
bash scripts/serve_qwen_tools.sh
```

Wait for startup to complete. Terminal 2:

```bash
cd /home/spl/akram/SCIP-vvah-test
curl --noproxy '*' http://127.0.0.1:8001/v1/models
.venv/bin/python scripts/prepare_targets.py --offset 0 --limit 1
bash scripts/smoke.sh --model-config configs/qwen38-27b-fp8-256k.json
```

The workspace launcher uses the existing checkpoint/environment, native 262144
context, `qwen3` reasoning parser, `qwen3_coder` tool parser and one active model
sequence. VVAH's workers can queue multiple requests at that server. GPU fraction
0.95 was tested successfully, with 266756-token cache capacity. The user's
external launcher remains unchanged and defaults to 131072 context at GPU
fraction 0.90; a 256K startup at 0.90 failed its cache-capacity check. The
workspace launcher retains the same FP8 weights and default KV cache precision.

The earlier Qwen run `20261013T044135.638273Z-6429843b45889333` passed actual tool
replay but timed out at S2 on both 600-second attempts. It used the former
4096-token output cap. Its historical artifacts remain unchanged. Those results
do not validate the current upstream-budget configuration or establish accuracy.
The temporary test server was stopped after that run. This checkpoint has no
`MODEL_REVISION.txt`; automatic records mark its revision unavailable.

## VulnLLM-R-7B

Terminal 1:

```bash
cd /home/spl/akram/SCIP-vvah-test
bash scripts/serve_vulnLLM-R-7B_tools.sh
```

Terminal 2:

```bash
cd /home/spl/akram/SCIP-vvah-test
.venv/bin/python scripts/prepare_targets.py --limit 1
bash scripts/smoke.sh
```

This launcher uses the existing Qwen2.5 checkpoint template and installed Hermes
parser with 32768 context. Upstream 64000-token output requests cannot fit that
context. These runs preserve VVAH's settings and report incompatibility instead
of applying the earlier 4096-token workaround.

## Another local model

Copy `configs/local-model.example.json` and edit its five connection fields:

```json
{
  "model_name": "YOUR_SERVED_MODEL_ID",
  "model_dir": "/absolute/path/to/existing/model-and-tokenizer",
  "base_url": "http://127.0.0.1:8001/v1",
  "tokenizer_python": "/absolute/path/to/python-with-transformers",
  "context_limit": 262144
}
```

The ID must match `/v1/models`; use the same tokenizer/template as the server.
The endpoint must be local HTTP. No model is downloaded. If authentication is
required, use `SCIP_LOCAL_API_KEY`; credentials are not placed in JSON or traces.
Model-backed roles are selected through a per-run local-provider overlay.

```bash
.venv/bin/python scripts/run_baseline.py --limit 1 \
  --model-config configs/my-model.json
```

For a bounded number of targets with upstream execution budgets:

```bash
.venv/bin/python scripts/prepare_targets.py --offset 0 --limit 5
.venv/bin/python scripts/run_baseline.py --offset 0 --limit 5 --resume \
  --model-config configs/qwen38-27b-fp8-256k.json
```

The benchmark has 408 entries, 184 advisories and 166 unique repository/commit
pairs. `--limit` bounds targets, not elapsed time. Preparation is resumable and
exports exact commits without history. `--resume` skips completed matching
model/configuration targets and retries failures in fresh directories; it does
not resume VVAH stage checkpoints. No full benchmark is launched automatically.

The optional `configs/context32k.local.yaml` is an earlier experimental source
packing variant, enabled only through explicit `--profile-overlay`. It is not
part of the upstream-configuration baseline.

## Outputs and evaluation

The workspace does not need an existing `runs/` directory. The runner creates
it when an evaluation starts and prints a unique directory:

```text
runs/<UTC-timestamp>-<target-id>/
  target.json                 exact repository and commit
  model-config.json           served model, tokenizer, endpoint and limits
  revisions.json              harness/dataset/model provenance
  status.json                 completed/failed, exit codes and source checks
  state/                      per-run VVAH checkpoints and code graph
  scan.log                    upstream scan output
  tool-trace.jsonl            actual model requests and responses
  raw-findings.json           original FinalReport, only if one was produced
  converted.jsonl             model-evidence findings for VulnGym
  conversion-errors.jsonl     missing or invalid evidence
  evaluation-subset.jsonl     matching benchmark subset, outside agent scope
  evaluation.json            matching details and available recall
  scan-source/security-scan/  original report Markdown, SARIF and findings.json
```

The runner scans a disposable source copy, so outputs do not land in the
canonical `targets/<id>` source. Failed copies with no `security-scan` artifact
are removed; logs, source hashes, errors and evaluation stay preserved. Raw
findings are absent when the harness never produced them, rather than replaced
with an invented empty report.

Evaluation runs automatically. Re-run it for a particular recorded attempt:

```bash
.venv/bin/python scripts/evaluate_run.py runs/ACTUAL-RUN-DIRECTORY
```

To repeat conversion when an actual report exists:

```bash
.venv/bin/python scripts/convert_findings.py \
  runs/ACTUAL-RUN-DIRECTORY/raw-findings.json \
  runs/ACTUAL-RUN-DIRECTORY/target.json \
  runs/ACTUAL-RUN-DIRECTORY/converted.jsonl \
  runs/ACTUAL-RUN-DIRECTORY/conversion-errors.jsonl
```

Matching uses the same repository URL and commit, normalized exact file paths,
strict entry-point/source and critical-operation/sink direction, and ±5 lines
on both endpoints. Missing prediction locations are never filled from benchmark
annotations. See `BASELINE_PROTOCOL.md` for evidence semantics and limitations.

For completed supported subsets, read
`evaluation.json -> official_result -> recall`. Advisory recall is covered
advisories divided by selected usable advisories; entry recall is matched
entries divided by selected usable entries. Failed scans have
`official_result: null`. There are 49 range-bearing entries unsupported by the
supplied official integer-line matcher; the wrapper flags them and withholds
recall for affected subsets.

**Precision and F1 require an additional reviewed labeling protocol.** The
benchmark is not an exhaustive catalog of every vulnerability in these
projects. An unmatched prediction can be a real vulnerability outside its
annotations. Do not automatically label unmatched findings false positives.
After independent review defines TP, FP and FN consistently, deduplicates
predictions, and uses one evaluation unit, compute:

```text
precision = TP / (TP + FP)
recall    = TP / (TP + FN)
F1        = 2 * TP / (2 * TP + FP + FN)
```

Do not mix finding-level precision with advisory-level coverage and call that
F1. This setup currently computes benchmark recall/coverage, not precision,
accuracy or F1.

## Installation and checks

```bash
cd /home/spl/akram/SCIP-vvah-test
UV_CACHE_DIR="$PWD/.cache/uv" uv pip install \
  --python .venv/bin/python -r configs/harness-requirements.lock.txt
cp configs/baseline.local.yaml \
  harnesses/visa-vulnerability-agentic-harness/vvaharness/config/profiles/config.local.yaml
chmod 600 harnesses/visa-vulnerability-agentic-harness/vvaharness/config/profiles/config.local.yaml
.venv/bin/python scripts/test_boundaries.py
.venv/bin/python scripts/test_guard_integration.py
```

The requirements snapshot records versions, without cross-platform wheel hashes.
The serving environment and its PyTorch/CUDA packages are not changed. Boundary
checks cover upstream config preservation, progress reporting without termination,
context accounting, conversion and evaluation. The network boundary check needs
localhost binding but sends no accepted model-generation requests.
