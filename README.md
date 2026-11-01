# CryptoAPI-Bench

Start the local Qwen 3.5 9B model:

```bash
cd /home/spl/akram/SCIP-vvah-test
bash scripts/serve_qwen_3.5-9b.sh
```

Or start Qwen 3.8 27B FP8 instead:

```bash
cd /home/spl/akram/SCIP-vvah-test
bash scripts/serve_qwen_3.8-27b.sh
```

In `scripts/run_cryptoapi_bench.py`, keep only the settings block for your chosen model
uncommented. The default is Qwen 3.5 9B; to use 27B, comment out the 9B block and
uncomment the 27B block.

In another terminal, run CryptoAPI-Bench through VVAH, one file at a time:

```bash
cd /home/spl/akram/SCIP-vvah-test
.venv/bin/python -u scripts/run_cryptoapi_bench.py
```

## Evaluate results

From the project root, evaluate the latest saved session:

```bash
.venv/bin/python scripts/evaluate_cryptoapi_bench.py
```

To compare different sessions, evaluate each separately:

```bash
.venv/bin/python scripts/evaluate_cryptoapi_bench.py \
  --run-dir runs/cryptoapi-bench/2026-10-27_00-27-32_214596_EDT

.venv/bin/python scripts/evaluate_cryptoapi_bench.py \
  --run-dir runs/cryptoapi-bench/2026-10-28_12-49-45_344571_EDT
```

Replace `--run-dir` with your session directory, which contains all case folders.
Append `--details` to include each case's matching lines and classification.
The script reads `datasets/CryptoAPI-Bench/CryptoAPI-Bench_details.xlsx` automatically
and prints TP, FP, FN, TN, precision, recall, and F1 as JSON in the terminal.
Check `coverage.scored_cases` and `issues` to see which cases were included in each score.
