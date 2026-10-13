# SCIP VVAH research workspace

Evaluate the pinned Visa Vulnerability Agentic Harness against Tencent VulnGym
using an existing local OpenAI-compatible model server.

This repository includes the integration scripts, configuration, documentation,
VulnGym data and vendored VVAH source. The upstream projects retain their own
LICENSE and NOTICE files. Original URLs, commits and source checksums are saved
in `configs/upstream-revisions.json`.

Virtual environments, caches, model weights, prepared targets and experiment
outputs are excluded from Git. Recreate the environment and fetch only the
targets you need on each server. The model weights must already exist there.

## Clone onto another server

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

The requirements file references the harness directory relative to this checkout.
It recreates the harness environment; it does not install or upgrade vLLM,
PyTorch or CUDA in your model-serving environment.
The copy recreates VVAH's sanctioned, locally owned provider overlay. Its source
is tracked in `configs/`; the installed copy is intentionally Git-ignored.

Edit `model_dir`, `tokenizer_python` and `base_url` in the selected model JSON
for the destination server. Keep `model_name` consistent with its served ID and
`context_limit` consistent with the actual server limit. The launcher scripts
contain this server's existing model and vLLM paths; update those paths and
choose the GPU memory fraction for the destination machine, or start its
already-configured compatible model server directly.

Once the model server is ready:

```bash
.venv/bin/python scripts/prepare_targets.py --offset 0 --limit 1
bash scripts/smoke.sh --model-config configs/qwen38-27b-fp8-256k.json
```

VVAH's shipped profile controls detection budgets and worker counts. The runner
uses local provider integration and detection through S9, then converts findings
and evaluates the matching VulnGym subset. New outputs go under `runs/` and
stay local.

See [setup instructions](docs/SETUP.md) and the
[baseline protocol](docs/BASELINE_PROTOCOL.md) for configuration, result paths,
matching rules and known validation limitations.
