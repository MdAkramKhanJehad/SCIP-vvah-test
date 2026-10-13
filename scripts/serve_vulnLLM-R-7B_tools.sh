#!/usr/bin/env bash
# Optional replacement for plain-chat serving. Stop the identified plain server
# yourself before running this; this script never stops another process.
set -euo pipefail
SCIP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCIP_GPU_MEMORY_UTILIZATION="${SCIP_GPU_MEMORY_UTILIZATION:-0.60}"
mkdir -p "$SCIP_ROOT/runs/server" "$SCIP_ROOT/.cache/hf" "$SCIP_ROOT/.cache/tmp"
export HF_HOME="$SCIP_ROOT/.cache/hf" TMPDIR="$SCIP_ROOT/.cache/tmp"
export HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1
printf 'GPU memory fraction: %s; context: 32768; concurrent sequences: 1\n' "$SCIP_GPU_MEMORY_UTILIZATION"
exec /scratch/mkhan04/qwen38-vllm/vllm-env/bin/vllm serve \
 /scratch/mkhan04/local_models/vulnLLM-R-7B \
 --served-model-name vulnllm-r-7b --host 127.0.0.1 --port 8002 \
 --dtype bfloat16 --tensor-parallel-size 1 --gpu-memory-utilization "$SCIP_GPU_MEMORY_UTILIZATION" \
 --max-model-len 32768 --max-num-seqs 1 --max-num-batched-tokens 2048 \
 --generation-config vllm --enforce-eager \
 --enable-auto-tool-choice --tool-call-parser hermes
