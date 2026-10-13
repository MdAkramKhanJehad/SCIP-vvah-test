#!/usr/bin/env bash
set -euo pipefail
SCIP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCIP_ROOT"
exec .venv/bin/python scripts/run_baseline.py --limit 1 "$@"
