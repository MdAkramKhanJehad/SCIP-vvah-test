# SCIP VVAH research workspace

Evaluate the pinned Visa Vulnerability Agentic Harness on Tencent VulnGym using
an existing local OpenAI-compatible model server. This snapshot has **23
repositories, 166 repository/commit targets, 184 advisories and 408 annotated
entry paths**. Each target is scanned once per model/profile experiment.

VulnGym and VVAH source are included. Their LICENSE and NOTICE files remain in
place; upstream commits and checksums are in `configs/upstream-revisions.json`.
Model weights, environments, prepared sources, caches and results are excluded
from Git. On a shared drive, use the **same checkout and `runs/` directory on
all servers** so they share the queue.

## 1. Install the harness environment

For a new checkout:

```bash
git clone --branch master https://github.com/MdAkramKhanJehad/SCIP-vvah-test.git
cd SCIP-vvah-test
UV_CACHE_DIR="$PWD/.cache/uv" uv venv --python 3.12 .venv
UV_CACHE_DIR="$PWD/.cache/uv" uv pip install \
  --python .venv/bin/python -r configs/harness-requirements.lock.txt
cp configs/baseline.local.yaml \
  harnesses/visa-vulnerability-agentic-harness/vvaharness/config/profiles/config.local.yaml
chmod 600 harnesses/visa-vulnerability-agentic-harness/vvaharness/config/profiles/config.local.yaml
```

Do this once for a shared checkout, before starting workers. The existing shared
checkout is `/home/spl/akram/SCIP-vvah-test`. A shared environment requires
compatible Python paths, operating systems and dependencies on every server.
These commands do not change the separate vLLM/PyTorch/CUDA environment.

## 2. Start a model on each worker server

In a separate terminal on **each server**:

```bash
cd /home/spl/akram/SCIP-vvah-test
bash scripts/serve_qwen_tools.sh
```

Wait for vLLM to report that the API server is ready. The launcher uses this
installation's existing model/environment paths. For another installation or
model, adjust the launcher and copy a model JSON under `configs/`. Set
`model_name`, `model_dir`, `tokenizer_python`, `base_url` and `context_limit` to
match that server. Tool calling must work; plain chat alone is insufficient.

The examples below use `configs/qwen38-27b-fp8-256k-nonthinking.json`, which
explicitly requests non-thinking mode. Use the same model and profile settings
on every server participating in the same experiment. Each server connects to
its **own** `127.0.0.1:8001` model, through its own local port-8003 request proxy.

## 3. Check one target first

```bash
.venv/bin/python scripts/run_baseline.py --offset 1 --limit 1 --prepare-missing \
  --model-config configs/qwen38-27b-fp8-256k-nonthinking.json
```

Equivalent smoke command:

```bash
bash scripts/smoke.sh --prepare-missing \
  --model-config configs/qwen38-27b-fp8-256k-nonthinking.json
```

This selects the second manifest target: Flowise commit
`1ae1638ed972bcc913611ae9268a972d0ae127ec`. Pass `--offset N` to select another
manifest position. Smoke runs the full detection workflow through S9 for one
target; it does not shorten VVAH's stages. Matching completed targets are skipped.
Use `--retry-failed` to retry a failure recorded by the shared scheduler, or
`--rerun-completed` to deliberately repeat a completed target in a new directory.

## 4. Run continuously across multiple servers

After checking the setup, run this **same command once on each server**, from
the shared checkout:

```bash
cd /home/spl/akram/SCIP-vvah-test
.venv/bin/python -u scripts/run_baseline.py --offset 0 --limit 166 --prepare-missing \
  --model-config configs/qwen38-27b-fp8-256k-nonthinking.json
```

This command authorizes considering the full dataset; it is not executed by
installation or tests. Start with `--limit 5` instead to restrict every worker
to the same first five candidates.

Each worker atomically claims an available repository/commit, prepares missing
source, runs detection, saves conversion/evaluation outputs, and moves to the
next available candidate. Workers skip commits claimed by another server and
matching completed targets. A failed scan is recorded and the worker continues.
**When no available targets remain in its selected range, the worker exits.**
It does not wait for other workers or repeatedly retry failures.

`--limit` is the number of manifest candidates considered, including skipped
ones, not the number each server must finish. Servers need no separate offsets
when working from the same range. Only one wrapper may run per server because
its local proxy uses port 8003. Do not run standalone `prepare_targets.py` on
sources while workers are preparing the same targets; use `--prepare-missing`.
Stop older, pre-update runners before starting these workers.

The default command preserves VVAH's shipped detection-stage controls. To use
the existing experimental profile with disabled stage clocks, two S4/S6 workers
and tool-based source access, append this option on **every worker**:

```bash
--profile-overlay configs/no-stage-timeouts-tools.local.yaml
```

For VVAH's shipped worker counts (S4: 12; S6: 7) with the same disabled
stage clocks and tool-based source access, use this overlay instead:

```bash
--profile-overlay configs/no-stage-timeouts-tools-upstream-workers.local.yaml
```

For higher finite stage timeouts with 12 S4 / 7 S6 workers and up to 12 active
model sequences, use these two terminals on **each machine**.

**Terminal 1 — Qwen server.** If Qwen is already running, stop it in its owning
terminal before restarting with the new sequence capacity:

```bash
cd /home/spl/akram/SCIP-vvah-test

SCIP_MAX_NUM_SEQS=12 bash scripts/serve_qwen_tools.sh
```

Wait until the API server reports that it is ready. Twelve active sequences at
a 256K context have not been validated on this 48 GB GPU; available KV-cache
memory determines actual concurrency. S4 and S6 run at different stages, so
their worker counts are not added together.

**Terminal 2 — harness worker.** Run the same command on every machine from
the shared checkout:

```bash
cd /home/spl/akram/SCIP-vvah-test

.venv/bin/python -u scripts/run_baseline.py \
  --offset 0 --limit 166 --prepare-missing \
  --model-config configs/qwen38-27b-fp8-256k-nonthinking.json \
  --profile-overlay configs/timeouts1200-tools-upstream-workers.local.yaml
```

This sets detection stage/session budgets below 1200 seconds to **1200 seconds**,
keeps the S8 session timeout at **1800 seconds**, uses 12 S4 / 7 S6 workers and
retains tool-based source access. Resume/replay attempts have their own budgets,
so 1200 seconds is not an overall scan or stage-duration cap. This profile is
separate from both the native-default and disabled-clock profiles. Pass it to
the smoke or main runner, and use it consistently for retries and every server.

These are upstream defaults, not a fixed maximum. The model launcher still
allows two active sequences by default; additional agent requests queue.
Neither this profile nor twelve simultaneous model requests have been validated
by a real multi-server scan.

That profile is a declared experiment variant. Server capacity and local-model
integration must also be reported when describing the baseline.

## 5. Check progress or retry failures

From any server, including one with an active worker:

```bash
.venv/bin/python scripts/run_baseline.py --status
```

The JSON lists active claims and the latest attempt for each target/experiment,
including hostname, PID, timestamps and run directory when created. Detailed
stage updates appear in each worker's terminal and its `scan.log`.

To make one more pass that includes previously failed/interrupted targets:

```bash
.venv/bin/python -u scripts/run_baseline.py --offset 0 --limit 166 --prepare-missing \
  --retry-failed --model-config configs/qwen38-27b-fp8-256k-nonthinking.json
```

Claims under `runs/.claims/` are shared across all configurations, preventing
simultaneous scans of the same commit. Completion/failure records under
`runs/.target-status/` are scoped to model/profile settings and upstream/model
revisions. `--resume` remains accepted; completed-target skipping is now automatic.
Historical completed matching runs are also recognized. Historical failures
created before this scheduler have no queue record and get one new attempt.

Ctrl+C or SIGTERM normally stops the active subprocess group, records an
interruption and releases the claim. A server crash or SIGKILL can leave an
abandoned claim. Claims **never expire automatically**. Check `owner.json` on
the recorded host and confirm both the wrapper and its scan subprocesses have
stopped before manually removing that claim's `owner.json` and empty directory.
An incomplete claim directory also blocks work and needs the same inspection.
Do not delete the entire claims directory while workers are active.

## 6. Find outputs and evaluate them

Each attempt uses its own directory:

```text
runs/YYYY-MM-DD_HH-MM-SS_<commit12>_<owner-repo>_<EDT-or-EST>/
  execution.json                          worker/claim information
  scan.log                                VVAH progress and diagnostics
  scan-source/security-scan/findings.json  native VVAH final findings, if produced
  raw-findings.json                       preserved final report copy
  converted.jsonl                         benchmark-format predictions
  conversion-errors.jsonl                 missing/unsupported predicted evidence
  status.json                             completed/failed and reason
```

Evaluation files are saved alongside these outputs; see
[exact evaluation outputs and matching rules](docs/SETUP.md#outputs-and-evaluation).
The wrapper automatically runs conversion and evaluates the selected target's
benchmark subset. Failed/degraded scans are not valid completed evaluations.
Unmatched findings are not automatically false positives. VulnGym supports
entry-level and advisory-level recall; precision and F1 require additional
validated labeling. Missing predicted locations are never filled from ground truth.

Canonical sources stay under `targets/` without Git history or benchmark
annotations; VVAH scans a disposable source copy. Model traces and logs remain
under `runs/` on the shared drive, excluded from Git.

See [SETUP.md](docs/SETUP.md) and [BASELINE_PROTOCOL.md](docs/BASELINE_PROTOCOL.md)
for detailed configuration, budgets and known model/evaluation limitations.

Scheduler validation (synthetic targets; no inference):

```bash
PYTHONDONTWRITEBYTECODE=1 .venv/bin/python -m unittest discover \
  -s scripts -p test_shared_runner.py -v
```
