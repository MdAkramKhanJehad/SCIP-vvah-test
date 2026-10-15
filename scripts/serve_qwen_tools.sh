#!/usr/bin/env bash
# Existing Qwen checkpoint and installed serving packages; relocated paths.
set -euo pipefail

SCIP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCIP_GPU_MEMORY_UTILIZATION="${SCIP_GPU_MEMORY_UTILIZATION:-0.95}"
SCIP_MAX_NUM_SEQS="${SCIP_MAX_NUM_SEQS:-2}"
mkdir -p "$SCIP_ROOT/.cache/hf" "$SCIP_ROOT/.cache/tmp"
export HF_HOME="$SCIP_ROOT/.cache/hf" TMPDIR="$SCIP_ROOT/.cache/tmp"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1

printf 'Qwen: context 262144; output allowance configured separately; sequences %s; GPU fraction %s\n' \
    "$SCIP_MAX_NUM_SEQS" "$SCIP_GPU_MEMORY_UTILIZATION"

SCIP_VLLM_ENV="/home/spl/akram/local_models/qwen38-vllm/vllm-env"
exec "$SCIP_VLLM_ENV/bin/python" "$SCIP_VLLM_ENV/bin/vllm" serve \
    /home/spl/akram/local_models/qwen38-vllm/models/Qwen3.8-27B-FP8 \
    --served-model-name qwen38-27b-fp8 --host 127.0.0.1 --port 8001 \
    --tensor-parallel-size 1 --gpu-memory-utilization "$SCIP_GPU_MEMORY_UTILIZATION" \
    --max-model-len 262144 --max-num-seqs "$SCIP_MAX_NUM_SEQS" --max-num-batched-tokens 2048 \
    --language-model-only --enforce-eager \
    --default-chat-template-kwargs '{"enable_thinking": false}' \
    --reasoning-parser qwen3 --enable-auto-tool-choice --tool-call-parser qwen3_coder
