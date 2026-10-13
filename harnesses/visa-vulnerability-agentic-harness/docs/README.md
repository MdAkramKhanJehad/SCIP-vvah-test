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

# Documentation

Start with the operator guide:

| Guide | |
|---|---|
| [User Guide](USER_GUIDE.md) | Install, credentials, configuration, commands, results, and troubleshooting |

Reference docs:

| Doc | |
|---|---|
| [Models](models.md) | Model roles & backend swap |
| [Architecture](architecture.md) | Pipeline stages, data flow, guardrails, outputs (Markdown, SARIF, manifest, exit codes) & `repos.csv` batch input |
| [Integrations](integrations.md) | Plugin & SDK model, data schemas, Semgrep modes A/B |
| [Operational Security](security.md) | Isolation, redaction, data egress |
| [Skills](SKILLS.md) | Security-analysis lenses built into the pipeline |
| [Limitations](limitations.md) | Design limits to know before you rely on a result |
| [Reporting issues](contributor-issue-guide.md) | How to file bug, documentation, and setup reports via GitHub issue forms |
| [Security policy](../SECURITY.md) | How to report a vulnerability privately, and how the tool handles your data |
| [Agent operating manual](../AGENTS.md) | Rules and commands for AI coding agents that run vvaharness |

Features & combinations:

| File | |
|---|---|
| [Features & Capabilities](features.md) | Capabilities, shipped profiles, model routes, and how to run discovery, remediation, validation and exploit verification, with their limits. |
| [Errors and Exit Codes](errors.md) | Public error codes, process exit codes, recovery actions, and artifact locations. |
