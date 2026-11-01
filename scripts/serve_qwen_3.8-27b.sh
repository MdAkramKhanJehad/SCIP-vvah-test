#!/usr/bin/env bash
# Serve the existing Qwen 3.8 27B FP8 model with tool calling and thinking disabled.
set -euo pipefail

# Override this with a native vLLM environment when using a different server architecture.
SCIP_VLLM_ENV="${SCIP_VLLM_ENV:-/home/spl/akram/local_models/qwen38-vllm/vllm-env}"
SCIP_VLLM_PYTHON="$SCIP_VLLM_ENV/bin/python"

if ! "$SCIP_VLLM_PYTHON" -c 'import sys' >/dev/null 2>&1; then
  printf 'Cannot execute %s on %s (%s). Set SCIP_VLLM_ENV to a native vLLM environment.\n' \
    "$SCIP_VLLM_PYTHON" "$(hostname)" "$(uname -m)" >&2
  exit 1
fi

if [[ -f "$SCIP_VLLM_ENV/bin/activate" ]]; then
  source "$SCIP_VLLM_ENV/bin/activate"
fi

exec "$SCIP_VLLM_PYTHON" -m vllm.entrypoints.cli.main serve \
  /home/spl/akram/local_models/qwen38-vllm/models/Qwen3.8-27B-FP8 \
  --served-model-name qwen38-27b-fp8 \
  --host 127.0.0.1 \
  --port 8001 \
  --tensor-parallel-size 1 \
  --gpu-memory-utilization 0.55 \
  --max-model-len 262144 \
  --max-num-seqs 1 \
  --max-num-batched-tokens 2048 \
  --language-model-only \
  --enforce-eager \
  --reasoning-parser qwen3 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_coder \
  --default-chat-template-kwargs '{"enable_thinking": false}'
