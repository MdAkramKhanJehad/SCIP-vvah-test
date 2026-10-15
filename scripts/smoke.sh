#!/usr/bin/env bash
set -euo pipefail
SCIP_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$SCIP_ROOT"
if [[ ! -x "$SCIP_ROOT/.venv/bin/python" ]]; then
    printf 'Missing harness environment: %s/.venv. Follow docs/SETUP.md, Installation and checks.\n' "$SCIP_ROOT" >&2
    exit 1
fi

# Default: second manifest repository/commit; --offset N overrides this selection.
exec .venv/bin/python scripts/run_baseline.py --limit 1 --offset 1 "$@"
