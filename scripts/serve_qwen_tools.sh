#!/usr/bin/env bash
# Existing Qwen checkpoint/environment; the original external launcher is unchanged.
set -euo pipefail

SCIP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCIP_GPU_MEMORY_UTILIZATION="${SCIP_GPU_MEMORY_UTILIZATION:-0.75}"
mkdir -p "$SCIP_ROOT/.cache/hf" "$SCIP_ROOT/.cache/tmp"
export HF_HOME="$SCIP_ROOT/.cache/hf" TMPDIR="$SCIP_ROOT/.cache/tmp"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1

printf 'Qwen: context 262144; output allowance configured separately; sequences 1; GPU fraction %s\n' \
    "$SCIP_GPU_MEMORY_UTILIZATION"

exec /scratch/mkhan04/qwen38-vllm/vllm-env/bin/vllm serve \
    /scratch/mkhan04/qwen38-vllm/models/Qwen3.8-27B-FP8 \
    --served-model-name qwen38-27b-fp8 --host 127.0.0.1 --port 8001 \
    --tensor-parallel-size 1 --gpu-memory-utilization "$SCIP_GPU_MEMORY_UTILIZATION" \
    --max-model-len 262144 --max-num-seqs 1 --max-num-batched-tokens 2048 \
    --language-model-only --enforce-eager \
    --reasoning-parser qwen3 --enable-auto-tool-choice --tool-call-parser qwen3_coder
