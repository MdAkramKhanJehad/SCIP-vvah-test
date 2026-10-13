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
# CLAUDE.md

**Read `AGENTS.md` in full before doing anything in this repo.** It is the
operating manual for running vvaharness.

vvaharness is a *released* CLI security-scanning product — operate it, don't
develop or repair it. A hand-edited tool gives unsupported, non-reproducible results.

Critical rules (full details in AGENTS.md):
1. Never edit files under `vvaharness/` to make a scan run.
2. Never hand-write config — use a shipped profile via `--config`. The one
   sanctioned exception is a git-ignored `config.local.yaml` overlay.
3. On any failure run `vvaharness setup` / `vvaharness doctor`, fix the
   environment it points to, and re-run. Report bugs; don't patch around them.
4. Scan only code the user is authorized to scan. Never arm exploit
   verification or fix mode unless the user asks: exploit verification sends
   live attack traffic, and fix mode edits the user's source.

Before you scan: prompts send target source to the configured model provider;
scans spend real tokens, so run `vvaharness estimate --repo <path>` first (no
spend).

Detection-only quick start: `uv sync` → `uv run vvaharness setup` →
`uv run vvaharness scan --repo <path> --stop-after s9`. `pipx install .` /
`pip install .` also work and need no extra index, because the vendored
code-graph SDK ships inside the `vvaharness` distribution.

> [!WARNING]
> **S10 remediation can edit the target's source.** The packaged default
> profile disables S10 remediation and S11 validation; `sdk` and `full` enable
> both. `--remediate` enables S10 only; in-scan S11 needs
> `step_validate.enabled: true`. `--stop-after s9` skips both with any profile.

> [!WARNING]
> **Exploit verification (Beta, API only) sends live attack traffic**, including
> state-changing requests, to a localhost target. It needs a
> Postman/OpenAPI/Swagger collection and checks only findings that map to an HTTP
> endpoint; all others stay static-analysis only. It turns on when
> `EV_API_COLLECTION` is set — a stale value in `.env` counts — and `--resume`
> turns it back on for a run that had it, even with the variable unset. To send no
> traffic, unset `EV_API_COLLECTION` and start a fresh run without `--resume`.
