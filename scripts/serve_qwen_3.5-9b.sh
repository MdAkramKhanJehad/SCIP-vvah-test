#!/usr/bin/env bash
# Same serving settings as /home/spl/akram/local_models/run_qwen3.5-9b.sh,
# with thinking disabled explicitly. Uses the existing environment and weights.
set -euo pipefail

source /home/spl/akram/local_models/qwen38-vllm/vllm-env/bin/activate

exec vllm serve /home/spl/akram/local_models/qwen3.5-9b \
  --served-model-name qwen35-9b \
  --host 127.0.0.1 \
  --port 8005 \
  --tensor-parallel-size 1 \
  --dtype bfloat16 \
  --language-model-only \
  --max-model-len 262144 \
  --gpu-memory-utilization 0.85 \
  --max-num-seqs 1 \
  --max-num-batched-tokens 8192 \
  --enable-prefix-caching \
  --max-cudagraph-capture-size 1 \
  --reasoning-parser qwen3 \
  --enable-auto-tool-choice \
  --tool-call-parser qwen3_coder \
  --default-chat-template-kwargs '{"enable_thinking": false}'
