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

# Integrations

Extend vvaharness with a **plugin**, or drive it from your own code with the **SDK**. The SDK
needs no change to vvaharness. A plugin needs one line added to vvaharness, its
`BUILTIN_PLUGINS` entry: only built-in plugins load, so a profile cannot run arbitrary code.

Semgrep is the reference integration and ships two ways in — use this to pick one:

| | Mode A | Mode B |
|---|---|---|
| You want | Semgrep run as part of the scan | your existing Semgrep report verified |
| vvaharness detects | independently, as usual | no S2–S4 discovery; S5 detectors and S6 can add findings |
| Model spend | full pipeline | S2–S4 skipped; auto-step1, S6 and S8 still call models |

For the plugin-author walkthrough in depth, see
[the SDK README](../vvaharness/sdk/README.md).

## Write a plugin

Satisfy one Protocol. `VvahPlugin` is `runtime_checkable`, so conformance is the contract —
no base class, nothing to register at import time.

```python
from vvaharness.sdk import Contribution, PluginInfo

class MyPlugin:
    @property
    def info(self) -> PluginInfo:
        return PluginInfo(name="myscanner", version="1")

    def contribute(self) -> Contribution:
        return Contribution(
            enrichers=(MyGraphEnricher(),),        # write onto the code graph
            graph_tools={"GraphMyThing": build},   # tools S2/S4/S6 may call
            subagents=(my_specialist(),),          # accepted; no stage runs them
        )
```

Every `Contribution` field is optional, so fill only the seams you need:

- **`enrichers`** reach `Workspace.analyze`, so every graph query downstream sees them. They
  are `context_graph_sdk.plugins.GraphEnricher`, re-exported rather than redefined.
- **`graph_tools`** reach S2, S4 and S6, advertised and budgeted together.
- **`subagents`** are accepted, but no stage runs them.

Two rules keep a plugin from breaking the scan:

1. **Never raise.** A plugin that raises fails the whole scan before S1, with exit code 1.
   Return a node whose property records what went wrong instead, so the scan continues and the
   failure stays visible in the graph.
2. **Bound your own I/O.** The 300s plugin deadline is cooperative and cannot interrupt a
   blocked callback, so a hung `enrich()` hangs the analysis.

## Run Semgrep inside a scan (mode A)

Run the shipped `semgrep.yaml` profile to give S2, S4 and S6 Semgrep evidence. It already
loads the plugin with the `p/security-audit`, `p/python` and `p/secrets` registry rulesets,
which Semgrep fetches over the network.

> **Install `semgrep` on `PATH` first.** Without it, the scan continues, but Semgrep results
> are absent or incomplete.

```bash
vvaharness scan --repo <path> --config vvaharness/config/profiles/semgrep.yaml
```

Semgrep output becomes a subgraph that S2, S4 and S6 query through four read-only tools:
`GraphSemgrepFindings`, `GraphSemgrepTaintTrace`, `GraphSemgrepSinkCallers` and
`GraphSemgrepCoverage`. Semgrep is evidence here, not a verdict — findings are still
discovered by the pipeline.

To use your own rule files, never edit the shipped profile: add a git-ignored
`config.local.yaml` beside it. Three overlay rules decide what survives:

- Mappings deep-merge, so the profile's `sdk` credentials stay.
- Lists replace, so `plugins` must restate every plugin entry you want.
- Use one `sdk:` key. YAML keeps only the last of two, so the first one's keys are lost.

```yaml
# config.local.yaml, beside semgrep.yaml
sdk:
  plugins:
    - name: semgrep
      configs: ["/absolute/path/to/local-rules.yml"]   # local rule files only
      # rulesets: ["p/python"]                          # registry rules, fetched over the network
```

See [Select and safely override a profile](USER_GUIDE.md#select-and-safely-override-a-profile)
for the overlay's ownership rules.

Only names in `BUILTIN_PLUGINS` resolve; `semgrep` is the only entry. A dotted import path is
deliberately refused, since a profile naming an arbitrary module would make config a
code-execution surface. Every key except `name` is passed to your constructor as a keyword.

## Verify findings you already have (mode B)

Mode B verifies, dedupes and reports findings from an existing Semgrep report, with no S2–S4
discovery spend. Convert the report, seed the S4 checkpoint in a fresh state directory, and
resume.

> **Use a fresh, empty `VVAHARNESS_STATE_DIR` for each handoff.** `inject_findings` writes
> only the s2–s4 checkpoints. If an earlier scan of the same path left s5–s8 checkpoints in
> the state directory, `resume=True` resumes those instead of verifying your findings. See
> [SDK](features.md#sdk-integrate-discovery-in-python).

```python
import os
import tempfile

from vvaharness.plugins.semgrep import findings_from_semgrep
from vvaharness.sdk import ScanOptions, inject_findings, scan

os.environ["VVAHARNESS_STATE_DIR"] = tempfile.mkdtemp(prefix="vvah-handoff-")
repo     = "/path/to/app"
findings = findings_from_semgrep("semgrep.json", repo=repo)   # repo= is REQUIRED
handoff  = inject_findings(repo, findings)                    # seeds s4, and s2+s3 as empty

scan(ScanOptions(repo=repo, resume=True, stop_after="s9"))    # S5 onward: your findings plus S5/S6 additions
```

```
pre runs     auto-step1 (one model call)
s0  runs     deterministic         s5  runs     enrich, prefilter, detectors
--  builds   code graph            s6  runs     verify (agentic)
s1  runs     deterministic         s7  runs     dedupe
s2  SKIPPED  seeded empty          s8  runs     chain (model call) + report
s3  SKIPPED  seeded empty          s9  runs     SARIF
s4  SKIPPED  your findings
```

Every stage is gated on *its own* checkpoint, so seeding s4 alone would still run S2 and cost
a model call you did not ask for. `inject_findings` therefore seeds empty `s2` and `s3` as
well, reporting them on `Handoff.skipped`. Keep that default in a fresh state directory.
`skip_discovery=False` leaves `s2` and `s3` untouched, and the injection survives only when
real `s2` and `s3` checkpoints already exist for this state; otherwise S2–S4 run and replace
your findings.

s0 and s1 are not seeded: they make no model call, and S1's file inventory decides which
injected paths S5 keeps. The code graph S6 reads is built on every run, between s0 and s1. The
auto-step1 survey runs before s0 and makes one model call; pass
`extra_argv=("--no-auto-step1",)` to skip it.

Exploit verification turns on when `EV_API_COLLECTION` is set in the process environment, and it
sends live requests, including state-changing ones, to the target. Unset the variable for a
handoff that must send no traffic; see
[Exploit verification](features.md#exploit-verification-add-live-api-evidence).

## Drive a scan from your own code

`scan()` runs one scan from Python and returns its exit code, so automation needs no shell
wrapper.

> **`scan()` spends model tokens and sends target source to the configured model provider.**
> Run `vvaharness estimate --repo <path>` first; it spends nothing.

```python
from vvaharness.sdk import ScanOptions, scan

result = scan(ScanOptions(repo="/path/to/app", profile="semgrep", stop_after="s9"))
print(result.exit_code, result.argv)
```

`scan()` goes through `vvaharness scan`'s own entry point, so it inherits the config trust
gate that rejects a profile read from inside the scanned repo. It does not load `.env` or
write `run_manifest.json`, so export the credentials your profile needs first; see
[SDK](features.md#sdk-integrate-discovery-in-python). `ScanOptions.argv()` is public: print
it to reproduce any programmatic run on the command line.

> **`remediate()` edits target source by default** (`mode="fix"`). Pass
> `mode="report-only"` to get a proposed fix without edits, and run fix mode only on a copy
> of the target. See [SDK integration choices](features.md#sdk-integration-choices).

## Reference

### Plugin types

- **`PluginInfo`** — `name: str`, `version: str`, `priority: int = 100`. `name` and
  `version` must be non-empty. `name` is the identity: unique across the set, 64 chars max.
- **`Contribution`** — `enrichers: tuple = ()`, `graph_tools: Mapping = {}`,
  `subagents: tuple = ()`. `merge()` concatenates two and raises on tool-name collision.

### Finding fields

Four fields are required. The rest are filled in as a finding moves down the pipeline, so an
integrator supplies the first group and reads the others.

| Group | Fields |
|---|---|
| Required | `title: str`, `file: str` (repo-relative), `line_start: int`, `vuln_class: VulnClass` |
| Optional on input | `severity: Severity` (default `medium`), `origin: str` (e.g. `semgrep:<rule-id>`; rows S5 and S6 add carry `detector` or `s6_discovered`), `case_id: str` (kept when set; must be unique) |
| Written by S4 | `cwe`, `description`, `impact`, `exploit_scenario`, `recommendation`, `source_ref`, `sink_ref` |
| Written by S6 | `verdict` (`TRUE_POSITIVE`/`FALSE_POSITIVE`), `verdict_confidence` (0–10), `verdict_reason`, `is_repeat_clone` (a repeat-site copy S6 adds) |
| Written by S7 | `duplicates` |
| Written after S8 | `case_id`, when empty |
| Scoring and EV | `cvss_*`, `vsvs_*`, `offensive_priority`, `ev_*` |

Two closed vocabularies apply:

```
Severity    critical · high · medium · low · info

VulnClass   injection · unsafe-deserialization · logic-flaw · info-leak · race-condition ·
            use-after-free · heap-overflow · stack-overflow · format-string ·
            integer-overflow · type-confusion · other
```

An unmapped CWE folds to `other` rather than being dropped.

### Scan and handoff types

- **`ScanOptions`** — `repo` (required), plus `profile`, `stop_after`, `resume`,
  `application_id`, `repo_name`, `extra_argv`. Anything omitted keeps the CLI default; a bare
  `profile` name resolves to a shipped profile.
- **`ScanResult`** — `exit_code`, `argv`. `.ok` means exit 0.
- **`Handoff`** — `run_id`, `stage`, `finding_count`, `skipped`. Capped at 2,000 findings.

### Semgrep graph schema

The reference enricher writes these, and its tools query them:

| Element | Carries or connects |
|---|---|
| `SemgrepScan` node (exactly 1) | `complete`, `findingCount`, `errorCount`, `skippedCount`, `ruleCount`, `note` |
| `SemgrepRule` node (1 per rule) | `ruleId`, `cweIds`, `vulnerabilityClasses` |
| `SemgrepFinding` node (1 per result, at most 500, most severe kept) | `ruleId`, `filePath`, `semgrepStartLine`, `severity`, `message` |
| `FLAGGED_BY` edge | innermost existing symbol containing the line → the finding |
| `DETECTED_BY` edge | the finding → its rule |
| `TRACE_TOUCHES` edge | the finding → each traced symbol, with `step` and `role` |

Every finding always gets a `FLAGGED_BY` subject — symbol, else that path's `File` node, else
a minted `SemgrepLocation` — so a finding on a path the repo walk skipped is never invisible.

### Limits

At most 16 plugins and 8 plugin graph tools per scan; 2,000 injected findings. Semgrep runs once
per scan, for at most 120 s (`timeout_seconds`) or the remaining plugin deadline. Plugin order
is `(priority, name)`, so a set has exactly one order. Ambiguity always raises rather than
resolving quietly: a duplicate plugin name, a duplicate graph-tool name, a graph-tool name that
matches a built-in graph tool, or a non-conforming object.

## Gotchas

Three path rules decide whether an injected finding reaches S6. S5 records every drop: its
`[s5-enrich]` console line counts the drops, and the report lists each one under Dropped
Findings. Check both when S6 verifies fewer findings than you injected.

- **Pass `repo=` to `findings_from_semgrep`.** Semgrep emits *absolute* paths whenever it was
  given an absolute target, and vvaharness keys findings on repo-relative paths. Without
  `repo=`, S5 drops every finding as `file not in repo inventory`.
- **Inject only paths in `ContextPackage.all_files`.** Paths the repo walk excluded —
  vendored trees, prior `security-scan/` output, anything the profile's globs or the
  auto-step1 survey cut — cannot reach S6. Check `all_files` first.
- **Expect test-path drops.** S5 drops a finding on a test, mock, example, fixture or sample
  path unless it is a secret or point-of-occurrence finding, such as a hard-coded credential.

Also worth knowing: a `@tool` docstring becomes the JSON-schema `description` the model reads,
so write it as instruction and state what an empty result means. `PluginContext.configuration`
is always empty, so configure through your own constructor.

## See also

[The SDK README](../vvaharness/sdk/README.md) for the plugin-author walkthrough and the
reference variant read line by line · [User Guide](USER_GUIDE.md#tls-and-private-gateways) for the `sdk:` transport ·
[Architecture](architecture.md) for stage data flow · [Outputs](architecture.md#out) for report anatomy.
