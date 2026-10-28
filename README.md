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
