<!--
Copyright 2026 Visa, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

# Developer helper scripts

These **maintainer/debug utilities** explain a scan's scope rules and its investigation plan
without running a new scan. They are not part of the installed package: `pip install .` does not
install them. Run them from a source checkout where `vvaharness` is importable, for example after
`uv sync`:

```bash
uv run python scripts/<script>.py [args]
```

After `pip install -e .`, run `python3 scripts/<script>.py [args]` instead.

| Script | What it does |
|---|---|
| `show_exclusions.py` | Print the S1 exclusion rules (dirs / extensions / globs) and the size gate, tagging each rule as built-in vs config-supplied. Use it to see which rules a scan with the default config starts from. It takes no arguments: it reads `./config.yaml` if present, else the packaged default profile, plus a trusted `config.local.yaml` beside that file. It does not read `--config`, `--step1-config` or the auto-exclude overlay. It lists rules, not the files they match, and it does not show walk-time checks such as symlink containment or the `target/` build-marker test. |
| `inspect_units.py` | Inspect a scanned target's S1–S3 checkpoints — investigation units with risk rank, file count, LOC, languages and threat, plus threat coverage and taint reachability (orphaned-sink BFS; tune depth with `--max-hops`, default 12). `--file <path>` reports which unit(s) contain a file (and whether it was in scope or excluded by S1); `--json [path]` dumps the context, orphaned sinks, and units with their files as JSON to a file, or to stdout if no path is given. Run with `--repo <target>`. |

Before you run `inspect_units.py`:

- **Create the checkpoints first** with a scan that uses `--stop-after s3`. That scan makes model
  calls (the auto-exclude survey and S2), so it spends tokens.
- **Point it at the right state.** Checkpoints are read from the SQLite state DB at
  `$VVAHARNESS_STATE_DIR/vvaharness.db` (default `~/.vvaharness/state/vvaharness.db`), keyed by
  `run_id`, **not** from the target repo. The `run_id` is derived from the absolute `--repo`
  path — pass `--run-id` if the scan ran against a different path, and `--state-dir` to override
  the state root.
- Checkpoints are JSON validated against the package's per-step pydantic schema (size-capped).

The scripts are intentionally dependency-light and do not change scan outputs.
`inspect_units.py` opens the state DB through the product's store, which creates the DB or
migrates its schema when needed. Because the scripts live outside the `vvaharness` package, they
are excluded from the wheel by design; treat them as repo-local tooling.
