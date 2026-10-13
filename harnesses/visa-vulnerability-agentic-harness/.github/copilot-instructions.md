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
# GitHub Copilot instructions

This repo is **vvaharness**, a released CLI security-scanning product. The full
agent operating manual is in `AGENTS.md` at the repo root — follow it.

Do NOT modify the `vvaharness/` package or hand-write config files to make a
scan run. If a command fails, run `vvaharness setup` / `vvaharness doctor` with
the same `--config`, fix the environment (usually a missing credential or the
`ANTHROPIC_BASE_URL` gateway), then re-run. Report genuine bugs instead of
patching the source.

Scan only code the user is authorized to scan. Never arm exploit verification
or fix mode unless the user asks: exploit verification sends live attack
traffic, and fix mode edits source. Prompts send target source to the model
provider. Scans spend real tokens, so run `vvaharness estimate --repo <path>`
first (no spend).

Detection-only: `uv sync` → `uv run vvaharness setup` →
`uv run vvaharness scan --repo <path> --stop-after s9`. This is a uv project;
`pipx install .` / `pip install .` also work.

The packaged default sets `step_remediate.enabled: false` and
`step_validate.enabled: false`, so a plain scan using it skips S10/S11.
`sdk`, `full` or a local overlay can enable them. `--remediate` enables S10
only and can edit target source; in-scan S11 needs `step_validate.enabled: true`.
Standalone `remediate` defaults to fix mode and edits source
(`--mode report-only` only proposes fixes). Keep `--stop-after s9` to skip both
stages with any profile.

- **Beta — API only.** Exploit verification needs a Postman/OpenAPI/Swagger
  collection and can only verify findings that map to an HTTP endpoint;
  everything else stays SAST-only. It is localhost-only and sends live attack
  traffic. It turns on when `EV_API_COLLECTION` is set (a stale `.env` value
  counts), and `--resume` turns it back on for a run that had it. To send no
  traffic, unset `EV_API_COLLECTION` and start a fresh run without `--resume`.
