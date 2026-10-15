# Run VVAH on VulnGym with a local model

Work from `/home/spl/akram/SCIP-vvah-test`. The harness installation is `.venv`
(Python 3.12). Existing model files and installed serving package versions are unchanged.
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
The serving environment's interpreter symlinks, entrypoint shebangs,
activation files and `pyvenv.cfg` now resolve under `/home/spl/akram/local_models`.
The original model launchers also use that location. This fixes startup on
`isc2357-03`, where the compatibility symlinks created on `isc2357-02` do not
exist. Those `/scratch` symlinks are no longer required by these launchers.
Path repair changed no package versions and did not start a model or harness.
Original edited files and symlink targets were backed up under the workspace's
`.cache/model-path-repair-*/` directory. The repository launchers invoke the
relocated Python interpreter explicitly, bypassing console-script shebangs.

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
.venv/bin/python scripts/prepare_targets.py --offset 1 --limit 1
bash scripts/smoke.sh --model-config configs/qwen38-27b-fp8-256k-nonthinking.json \
  --profile-overlay configs/no-stage-timeouts-tools.local.yaml
```

The current workspace launcher uses the existing checkpoint/environment,
262144-token context, GPU fraction 0.95, `qwen3` reasoning parser,
`qwen3_coder` tool parser, and two active model sequences. Native thinking is
disabled by the default chat-template option. Use the non-thinking model JSON
so the guard forwards matching options and counts the matching template.
The launcher retains the same FP8 weights and default KV cache precision.
The two-sequence configuration has passed static configuration checks; GPU
startup and concurrent inference have not yet been tested. If startup rejects
KV-cache capacity, two sequences at this context need additional capacity or
a separately recorded serving adjustment.

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
.venv/bin/python scripts/prepare_targets.py --offset 1 --limit 1
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
exports exact commits without history. Matching completed targets are always
skipped (`--resume` is retained for compatibility). Scheduler-recorded failures
require `--retry-failed`; new attempts use fresh directories rather than VVAH
stage checkpoints. No full benchmark is launched automatically.

The optional `configs/context32k.local.yaml` is an earlier experimental source
packing variant, enabled only through explicit `--profile-overlay`. It is not
part of the upstream-configuration baseline.

## Outputs and evaluation

The workspace does not need an existing `runs/` directory. The runner creates
it when an evaluation starts and prints a unique directory:

```text
runs/<YYYY-MM-DD_HH-MM-SS>_<commit12>_<owner-repo>_<EDT-or-EST>/
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

Run names use 24-hour time in `America/New_York`, the first 12 characters of
the actual target commit, and repository owner/name. A same-second collision
adds `_02`, `_03`, etc.; results are never overwritten. For example:
`2026-10-14_12-27-19_1ae1638ed972_FlowiseAI-Flowise_EDT`.
Existing folders were renamed in place; `runs/directory-renames.json` records
original names. Historical absolute paths inside raw logs and reports remain
unchanged. Wrapper resume/evaluation discover files relative to the new folder;
reusing native checkpoints or commands with old absolute paths requires updating
those paths. No compatibility symlinks or duplicate result directories are made.

VVAH writes `scan-source/security-scan/findings.json`, Markdown and SARIF.
The wrapper copies that JSON unchanged to `raw-findings.json` and separately
writes conversion/evaluation artifacts. Interrupted runs may have no final
report or only VVAH's primary file before the wrapper reaches conversion.

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

## Longer detection time budgets

Use the timing variant explicitly for a new run:

```bash
./scripts/smoke.sh --model-config configs/qwen38-27b-fp8-256k.json \
  --profile-overlay configs/timeouts1200.local.yaml
```

It raises all configured detection-session time budgets below 1200 seconds:
S2's initial deadline, client timeout, resume and replay; S4's deadline, resume
and replay; S6's batch deadline, batch wall-clock ceiling, resume and replay;
and S8's deadline, resume and replay. S8's existing 1800-second client timeout
stays unchanged. Low-level file-tool timeouts and disabled exploit/remediation
stages are outside this variant.

This changes waiting budgets, not generation speed, output tokens, reasoning,
concurrency or source coverage. The 30-second progress heartbeat stays unchanged.
S2 can spend roughly 60 minutes across its initial/resume/replay attempts;
additional native retries can add time. S6's 1200-second batch wall-clock ceiling
can end a batch before its individual retry budgets are exhausted.

The existing runner must be stopped in its own terminal before starting another
run. Running processes retain the settings loaded at startup. New runs save
`profile-overlay.yaml`, effective settings in `limits.json`, and variant
provenance. The upstream profile remains unchanged; running without this option
still uses the original detection budgets. These results are a timing variant,
not the original upstream-budget baseline.

## Requests larger than the model context

Run `2026-10-13_23-06-43_24f847b84c94_BerriAI-litellm_EDT` failed because an S6 request
contained 160444 input tokens plus a 32000-token output allowance, exceeding
its actual 131072-token context. Its full-scan retry separately timed out in
model/tool preflight. A larger timeout cannot fix an oversized request.

For an explicit local-context variant, keep the actual model limit and use:

```bash
./scripts/smoke.sh --model-config configs/qwen38-27b-fp8-256k.json \
  --profile-overlay configs/timeouts1200-tools.local.yaml
```

This combines the 1200-second timing variant with `step4.inline_source: false`
and `step6_verify.inline_source: false`. These are native VVAH controls: the
agent reads source using its read-only tools instead of receiving full files
embedded in the initial prompt. S4 and S6 use one worker each, matching the
single-sequence model server. Files remain accessible; evidence scope, output
allowances, sampling and thinking settings stay unchanged.
This changes prompt assembly and must be compared as a separate profile variant.
It is not an upstream-default baseline.

The context guard stays enabled. Tool results and later history can still exceed
the context limit, and timeout changes do not guarantee successful completion.
The native preflight budgets (120 and 300 seconds) are not changed by this
stage overlay. Before retrying, check the model terminal or `/metrics` for
active/queued requests. If cancelled work remains, stop the identified model
server in its owning terminal and restart it, then wait until ready. Never
increase the JSON context limit beyond the actual server's context. Preserving
upstream whole-file inlining also requires fitting the native DeepAgents
prompt cap, which is independent of the actual server context.

## Verification failures at 256K context

Run `2026-10-14_00-25-20_24f847b84c94_BerriAI-litellm_EDT` used 262144-token context and
the timing-only overlay. It still encountered the native DeepAgents 150000-token
prompt cap, unrecovered S4 timeouts and six unrecovered S6 verification errors.
S4 had 12 workers and S6 had 7, while the server accepted one active sequence.
Its completed requests reported 46864 reasoning tokens out of 72055 generated
tokens; those counts exclude unreported usage on disconnected requests. The
proxy recorded 29 broken pipes, showing clients disconnected; this does not
establish whether the proxy caused or amplified cancellation delays.

Use the explicit tool-source/single-worker profile shown above for the next
pilot, not the timing-only profile. It changes prompt assembly and concurrency
and must remain a separately recorded integration variant. Long native Qwen
thinking remains enabled and can still cause timeouts. Disabling native thinking
would be an additional model-serving experiment requiring separate records
and a fresh compatibility check.

Exit code zero means VVAH wrote its report, not that all stages completed
successfully. The wrapper excludes only diagnostics explicitly marked
`recovered: true` from its failure check; malformed or unrecovered diagnostics
still fail the run, as does `report.degraded`. The old run remains unchanged
and failed because it contains unrecovered errors. No accuracy or zero-recall
claim should be made from its failed verification.

## Smoke target selection and disabled stage clocks

`smoke.sh` now defaults to manifest offset 1, selecting the second target in
lexicographic repository/commit order, independently of annotations:
FlowiseAI/Flowise at `1ae1638ed972bcc913611ae9268a972d0ae127ec`, target
`a7514e3b32ff8726`. The manifest's original smoke identifier describes the
historical first target; it remains unchanged. Explicit `--offset N` selects
another target, and preparation must use the matching offset.

```bash
.venv/bin/python scripts/prepare_targets.py --offset 1 --limit 1
./scripts/smoke.sh --model-config configs/qwen38-27b-fp8-256k.json \
  --profile-overlay configs/no-stage-timeouts-tools.local.yaml
```

The explicit profile uses supported zero values to disable detection-stage
session deadlines, resume/replay clocks, S2/S8 session timeouts and the S6 batch
ceiling. It uses two S4/S6 workers and native tool-based source reads, matching
the launcher's two-sequence limit. Worker settings apply to a new scan;
restart the model server after editing its sequence limit. The
wrapper already has no scan wall timeout; its 30-second wait only reports
progress. Native model-client request timeouts (1800-second high-tier anchor,
scaled by effort), preflight budgets, token caps and model/tool-call budgets
remain upstream-controlled. This is not a fully timeout-free configuration.
Existing processes keep their loaded configuration; this command starts a new
run once the current runner has finished or been stopped in its own terminal.

## Explicit non-thinking Qwen pilot

The launcher supports `--default-chat-template-kwargs '{"enable_thinking": false}'`.
Restart it in its owning terminal after editing. For matching request rendering,
use the separate model config, not the original five-field Qwen config:

```bash
./scripts/smoke.sh --model-config configs/qwen38-27b-fp8-256k-nonthinking.json \
  --profile-overlay configs/no-stage-timeouts-tools.local.yaml
```

The optional model-config field `chat_template_kwargs` currently accepts only a
boolean `enable_thinking`. When configured, the guard applies that setting to
actual model requests and uses the same setting for token counting. It preserves
messages, tool schemas, output allowances and other request parameters. Traces
record the effective request plus original template options in
`provider_adaptation`; the model configuration is saved with each run. Without
that optional field, requests are forwarded as before. This is an explicit
provider adaptation and non-thinking experiment, not evidence of identical
behavior to the thinking configuration. Tool calling remains enabled and the
native preflight must still pass. No completion or quality result is established
by the configuration checks alone.

The smoke default selects Flowise at manifest offset 1. Prepare it with the
matching offset if needed. Results and logs are saved in a new `runs/` directory.

## Upstream detection defaults with the local model

For the pinned VVAH default profile, S4 has 12 workers and S6 has 7 workers.
These are shipped defaults, not a documented maximum. The thread pools take
the configured worker count; increasing it beyond the defaults is a tuning
experiment, not a requirement for a base result.

The existing runner uses upstream detection settings when no `--profile-overlay`
is supplied:

```bash
./scripts/smoke.sh --model-config configs/qwen38-27b-fp8-256k-nonthinking.json
```

This keeps native deadlines, prompt assembly/inlining, output budgets, turn/call
limits and S4/S6 workers. It does not apply the no-clock/tool-source adaptations.
Native timeouts, prompt caps and model-call failures remain valid possible
baseline outcomes. Choosing default worker counts does not fix prior schema
or missing-location conversion failures.

The model server's capacity is a separate setting. Its launcher defaults to
2 active sequences. After stopping the identified existing server yourself,
a 12-sequence capacity trial can be requested explicitly:

```bash
SCIP_MAX_NUM_SEQS=12 ./scripts/serve_qwen_tools.sh
```

This is a capacity trial, not a verified configuration for 48 GB VRAM and 256K
context. vLLM may reject startup or schedule fewer requests because of cache
capacity. Do not change context/cache precision without recording it as a
separate serving configuration. Twelve harness workers can also run against
a two-sequence server, where excess model requests queue. Report the actual
server limit, queueing and failures; 12 configured workers do not establish
12-way GPU concurrency.

Use a precise label such as "VVAH default detection profile with local
Qwen-27B-FP8, non-thinking mode". This is a local-model baseline, not the full
stock deployment with its shipped remote-model assignments. Disclose local
provider routing, thinking mode, actual serving capacity, context, detection-only
scope and wrapper evaluation rules. Keep those model/serving settings fixed
when comparing later harness changes. The earlier adapted runs remain adapted
runs; their artifacts are not relabelled as upstream-default results.

## Installation and checks

The harness uses `.venv/`; a separate directory named `venv/` does not satisfy
that path. Virtual environments are excluded from Git, so create the harness
environment once after cloning onto a new server. These commands reuse the
existing Python installation and leave the vLLM environment unchanged.

```bash
cd /home/spl/akram/SCIP-vvah-test
UV_CACHE_DIR="$PWD/.cache/uv" UV_PYTHON_DOWNLOADS=never uv venv \
  --python /home/spl/akram/local_models/qwen38-vllm/uv-python/cpython-3.12.14-linux-x86_64-gnu/bin/python3.12 .venv
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


## Shared-drive workers

Follow the [main README](../README.md#4-run-continuously-across-multiple-servers)
for identical commands on each server. Workers use atomic shared-directory
claims keyed by repository/commit, continue to the next available target after
each attempt, and exit when the selected range is exhausted. `--prepare-missing`
fetches target sources while holding the claim. `--status` shows active owners
and latest attempts without acquiring a worker lock. Do not prepare the same
sources using a separate preparation process concurrently.

A shared lock on the old `.runner.lock` fences old exclusive-lock runners;
it no longer serializes the updated servers. Per-host locks protect the fixed
local port-8003 proxy. Active claims live in `runs/.claims/`; persistent attempt
records live in `runs/.target-status/`. Abandoned claims are not automatically
stolen. Inspect the recorded host and all scan processes before manual recovery.
