# CryptoAPI-Bench

Start the local Qwen 3.5 9B model:

```bash
cd /home/spl/akram/SCIP-vvah-test
bash scripts/serve_qwen_3.5-9b.sh
```

In another terminal, run CryptoAPI-Bench through VVAH, one file at a time:

```bash
cd /home/spl/akram/SCIP-vvah-test
.venv/bin/python -u scripts/run_cryptoapi_bench.py
```
