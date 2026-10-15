# Baseline protocol

The baseline uses the pinned upstream VVAH detector, the selected existing local
model, and the pinned VulnGym snapshot. Future harness improvements require
separate configurations and run directories with the same model and evaluation
protocol. No harness detection source or shipped prompt text is patched.
`configs/upstream-revisions.json` records original commits and source checksums
for the detached harness and dataset directories. No freeze file is required.

## Configuration authority

The user requested that VVAH's configuration control execution. The shipped
`vvaharness/config/profiles/default.yaml` therefore supplies all detection-stage
output budgets, prompt assembly controls, worker counts, deadlines, retries,
turn limits and model-call limits. The local overlay only selects local
DeepAgents/OpenAI Chat Completions roles, disables Anthropic cache markers for
this endpoint, and keeps exploit verification, remediation, validation and
report upload disabled. Detection stops after S9.

There are no wrapper probe/estimate/setup/scan timeouts, output caps, sampling
or seed overrides, or request serialization. The former `--wall-seconds` flag
and `configs/limits.json` were removed. Native VVAH model/tool preflight runs as
part of the scan; the independent marker probe is no longer invoked by the
runner. Stage messages and 30-second elapsed-time heartbeats are still printed.
Polling every 30 seconds does not terminate a process. Ctrl+C stops the runner's
active subprocess group; it does not stop the model server.

A failed scan triggers setup and one identical retry, following upstream's
operating instructions. There is no overall wrapper wall budget. `--limit`
limits repository/commit targets only. Each run saves the effective upstream
stage controls in its `limits.json`; absent outer limits are explicit nulls.

Examples of shipped controls: repository-survey output 8000 tokens; S2/S4
output 64000; S6 output 32000; S8 output 48000 and prompt budget 100000; S4
workers 12 and S6 workers 7. Existing S2/S4/S6/S8 model-call limits are 4/8/12/1.
DeepAgents max_turns is a recursion setting plus upstream headroom, rather than
a hard turn cap. Model clients retain upstream retry and timeout behavior.

The optional `configs/context32k.local.yaml` is a historical experimental
packing variant. It changes evidence assembly and is applied only with explicit
`--profile-overlay`; it is not the default baseline.

The optional `configs/timeouts1200.local.yaml` is a user-requested timing
variant, selected explicitly through `--profile-overlay`. It raises shorter
configured detection-session deadlines, resume/replay timeouts, the S2 client
timeout, and the S6 batch wall-clock ceiling to 1200 seconds. Longer budgets
remain unchanged. It does not change output budgets, workers, reasoning,
prompts or scope. Each run records its overlay and checksum as a
`profile-variant`; comparisons must distinguish it from the original upstream
budgets. A stage can include several attempts; 1200 seconds is not an overall
scan limit. The S6 batch ceiling bounds its attempts collectively.

The optional `configs/timeouts1200-tools.local.yaml` additionally disables
whole-file source inlining in S4/S6 using the native `inline_source` controls.
S4 and S6 also use one worker each to match the single-sequence server.
Source remains accessible to read-only agent tools. This addresses the observed
S6 initial request exceeding 131072 tokens; history and tool results remain
subject to context checks. It changes source presentation, not target selection
or evaluation matching. Runs record it separately as a profile variant; its
completion and performance have not been established. The stage overlays do
not change native preflight deadlines.

For an upstream-profile local-model baseline, omit `--profile-overlay`.
The runner then preserves all shipped detection-stage controls, including
12 S4 workers and 7 S6 workers. These are defaults, not a documented maximum.
Using a local non-thinking Qwen model is still an explicit model/provider
adaptation and must be disclosed. Higher worker counts, altered timeouts or
tool-source presentation are separate configurations.

Server capacity is independent of harness worker counts. The Qwen launcher
accepts `SCIP_MAX_NUM_SEQS`, default 2; setting it to 12 requests up to twelve
active sequences but has not been validated on this GPU at 256K context.
A two-sequence server may queue requests from 12 harness workers. Report its
actual configuration rather than claiming 12-way GPU execution. No previous
run is relabelled by this documentation or setting.

## Model connection and context

The selected JSON file has five required connection fields: served model name, existing
model/tokenizer directory, local HTTP endpoint, tokenizer Python and actual
server context limit. An optional `chat_template_kwargs` field explicitly
selects boolean `enable_thinking`; the guard applies it to actual requests
and matching tokenizer rendering, recording the adaptation in each trace.
The non-thinking Qwen JSON is a separate model configuration.
Model settings select every model-backed role, including
inactive roles and fallbacks, through a per-run overlay. No remote model or paid
API is used. API credentials are passed through environment variables and are
not recorded in traces.

The local proxy renders the model's unchanged template over system prompts,
tool schemas, history, source excerpts and tool results. An explicitly configured
thinking mode is a recorded provider adaptation. It preserves requested output
allowances and never inserts an output allowance when omitted. Input
plus explicitly requested output must fit the actual model context. It does
not truncate source/history or raise the server context. If the output allowance
is omitted, only input size can be checked; output capacity is then controlled
by the server. Reported token usage is preserved, while unavailable usage stays
unavailable. Assistant reasoning is included in replay token accounting using
the installed vLLM preprocessing conventions. The API payload is unchanged.

Qwen settings are `configs/qwen38-27b-fp8-256k.json`: served ID
`qwen38-27b-fp8`, port 8001, total context 262144. The workspace launcher uses
installed `qwen3` reasoning and `qwen3_coder` tool parsers, existing FP8 weights
and default KV cache precision. GPU fraction 0.95 was tested with cache capacity
266756 tokens; 0.90 failed the 256K cache-capacity check. The server has one
active sequence, while upstream VVAH worker requests may queue. The checkpoint
lacks MODEL_REVISION.txt, so automatic model revision is unavailable. Observed
config download metadata in the historical run is not proof of every weight's
revision.

VulnLLM uses the original local model at port 8002, context 32768 and the
verified Hermes parser for its Qwen2.5 tool-call template. Its recorded revision
is `8cd13d7a35f13b187102dba166413d4450836a40`. The launcher defaults to GPU fraction
0.60. Native 64000-token output allowances cannot fit this model's context;
the current protocol records the failure instead of shrinking VVAH's controls.

## Target selection and isolation

The full repository is scanned at the dataset's exact vulnerable commit. The
manifest groups entries by repository URL and commit, retaining all entry and
advisory mappings. It has 408 entries, 184 advisories and 166 target groups.
Groups are sorted lexicographically by `(repo_url, commit)` without consulting
known defect locations. Offset 0 selects BerriAI/litellm at
`24f847b84c947e13b765edaf172f646fd1b06297`, target ID `6429843b45889333`.
This deterministic first target is large and is not a representative sample.

Preparation fetches the exact SHA, exports its source without Git metadata, and
removes completed fetch caches. The runner scans a disposable `scan-source`
copy. Source hashes verify the canonical target and copied source are unchanged.
Upstream read-only tools are jailed to the target inventory, with shell access
disabled. Benchmark annotations, advisories, defect locations, fixes, traces,
manifest annotations and evaluation subsets remain outside the agent workspace.
They are used only by the external evaluator. Repository-authored documentation
may contain historical security information. This is tool-level source
isolation, not a host/container security boundary. No live attacks or target
applications are launched.

## Conversion and matching

Preserve native FinalReport findings independently from converted predictions
and conversion errors. Conversion accepts model-produced source_ref and
sink_ref evidence as entry point and critical operation, requiring safe
repository-relative paths and positive integer lines. It excludes deterministic
rule-origin rows and AST-backfilled endpoint references. Missing evidence is
explicit; no location is filled using ground truth or guessed from another
endpoint. Native findings remain triage candidates, not confirmed defects.

The official VulnGym evaluator is called with the matching repository/commit
subset and line tolerance 5. Matching uses normalized exact file paths and
strict source/entry-point and sink/critical-operation direction. Line-zero
entries follow the official skip policy. Advisory recall means at least one
entry matched in an advisory; entry recall counts matched benchmark entries.
Use the selected subset as the denominator. Evaluation is per target; there is
currently no aggregate batch score.

Failed, degraded or stage-error scans do not receive an official recall score.
Pipeline matching diagnostics may run on them, without treating absent output
as a successful empty prediction. The snapshot has 49 range-bearing entries
unsupported by the official integer-line matcher; affected subsets are flagged
and recall withheld rather than silently coercing ranges. Conversion errors and
unmatched findings remain separate from scan failures.

Precision, accuracy and F1 are not established by benchmark recall alone.
Unmatched predictions are not automatically false positives because annotations
are incomplete. A validated independent labeling protocol must define TP, FP,
FN, duplicate handling and a consistent evaluation unit before computing
precision = TP/(TP+FP), recall = TP/(TP+FN), F1 = 2TP/(2TP+FP+FN).
Do not combine advisory coverage with finding-level precision to form F1.

## Reproducibility and validation

Each unique run saves target/model settings, exact upstream commits and available
model revision, effective profiles and stage controls, integration hashes,
dependency versions, source hashes, provider request/response/tool traces,
reported token usage and timing, CLI logs, raw reports when produced, converted
findings, errors, evaluation subset and results. Upload credentials and
Authorization headers are never recorded. GPU energy, peak usage and missing
model usage measurements remain unavailable. Matching completed targets are
always skipped (`--resume` remains accepted). Scheduler-recorded failures require
`--retry-failed`; new attempts do not reuse VVAH stage checkpoints.

Historical runs retain their original limits and results. The Qwen run
`20261013T044135.638273Z-6429843b45889333` passed real tool replay and model
preflight but timed out at S2 twice under its then-active 600-second wall limit
and 4096 output cap. Earlier VulnLLM runs also failed under added budgets or
context constraints. Those runs do not validate the current upstream-budget
protocol and establish no model accuracy. Current boundary tests verify restored
configuration, progress polling without termination, context accounting,
conversion and matching. A complete detection run under the current protocol
has not yet been established.

Run status treats diagnostics explicitly marked `recovered: true` as recovered.
Unrecovered or malformed diagnostics and a degraded report still fail the run,
even if the harness exits with code zero. Raw diagnostics remain preserved.

The optional `configs/no-stage-timeouts-tools.local.yaml` disables supported
native detection-stage clocks using zero values; it uses two S4/S6 workers
and source through read-only tools, matching the two-sequence Qwen launcher. It does not disable native model-client
request timeouts, preflight budgets or token/model/tool-call limits. It is
recorded as a separate profile variant. The smoke launcher now selects manifest
offset 1 by default (FlowiseAI/Flowise at
`1ae1638ed972bcc913611ae9268a972d0ae127ec`); explicit offsets remain supported.
Historical target selections and manifests are not rewritten.

The two-worker/two-sequence change requires a server restart and a new run.
It preserves the configured 262144-token context and non-thinking mode.
Concurrent GPU startup/inference has not yet been validated; configuration
checks alone do not establish throughput or model quality.

Run directory names use 24-hour America/New_York time, a 12-character target
commit prefix, repository owner/name, and EDT/EST. Same-second collisions get
an additional numeric suffix. Exact commits remain in `target.json`. Existing
folders were renamed without editing raw run artifacts; old/new names are
recorded in `runs/directory-renames.json`. Historical absolute paths in the
artifacts remain historical, and native checkpoint reuse needs path handling.
The wrapper owns run directories; VVAH owns the original findings/report files.


## Shared-drive scheduling

Each worker considers an explicit manifest range (`--offset`, `--limit`). The
limit counts candidates, including skipped ones. An atomic directory claim is
keyed by repository URL and exact commit, across all experiment configurations.
One worker per host uses its own local model endpoint and request proxy. After
each attempt it takes the next unclaimed candidate; it exits when no candidates
remain available, without waiting for other workers or polling failed targets.

Persistent latest-attempt records distinguish model settings, available model
revision, provider overlay, native profile, optional stage overlay and upstream
commits. Matching successful runs are skipped automatically, including compatible
historical runs; scheduler-recorded failures/interruption require explicit retry.
Intentional repeats require `--rerun-completed`. Historical failures without a
scheduler record receive one new attempt. Originals and prior run directories
are preserved. No timing, output, tool, sampling or detection controls are
changed by scheduling. Identical model JSONs and profiles should be used across
servers in one experiment; host-specific JSON differences identify distinct
experiments, so do not mix them in the same queue pass.

Claims record hostname, PID, UTC start time, experiment identity and run path.
They are coordination state outside the scanning source tree. Normal completion
and handled interruption release the claim after recording the outcome. A crash
can leave a blocking claim, which has no automatic expiry: an operator must
verify that the owning wrapper and scan processes have stopped before removing
it. The shared filesystem must support atomic directory creation and rename;
local synthetic races do not establish multi-host correctness on every mount.
Read-only status snapshots can race with a claim being created or released and
must not be used as a substitute for claiming work.
