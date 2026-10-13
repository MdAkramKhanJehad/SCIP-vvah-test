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
# Security Skills

vvaharness gives its model sessions specialist security knowledge where a
decision is made: a session opens one playbook for the weakness family in front
of it. Code also adds fixed checklists: a threat-model baseline per repository
kind, CWE false-positive checks, and the S6 out-of-scope rules.

- **Fewer false positives.** Each playbook names the real mitigations and the
  traps that look like a bug but are not.
- **Consistent coverage.** Repositories of the same kind get the same checks.
- **Bounded prompt cost.** A session pays for a playbook body only when it opens one.
- **No target pollution.** The playbooks exist in the target only for the scan.

> Skills are prompt knowledge, not separate detectors. The configured model
> still reads the code and makes every verdict. A skill adds no findings itself.

## Key concepts

| Term | Meaning |
|---|---|
| Skill | A directory `vvaharness/skills/<name>/` with a `SKILL.md`: YAML frontmatter (`name`, `description`) and a Markdown body. |
| Lens / method | A lens covers one weakness family: what to look for, the real mitigations and the false-positive traps. Most lenses also set a hard gate: the evidence a finding needs. A method is a procedure, such as a sweep for siblings of a confirmed defect. |
| Probe | An optional read-only POSIX `sh` script (`probe.sh`) next to a `SKILL.md`. It greps a whole family in one call and prints labelled `path:line` hits. An empty section is evidence that a pattern is absent. |

## How a skill reaches a session

The harness decides deterministically which skills a session can see. The
model decides which skill to open, bounded by the prompt.

| Lifecycle step | What happens | Why |
|---|---|---|
| 1. Copy | On the first S2 or S4 session, the harness copies the packaged skills to `<target>/.vvaharness/skills/`, once per repository root per scan, under a lock. | Session tools are jailed to the target root, so the skills must be inside it. |
| 2. Refuse unsafe copies | The copy is skipped when `.vvaharness` is a symlink, when `.vvaharness/skills` already exists, or when a write fails. The stage then gets none of the packaged skills. Rename the target's own `.vvaharness/skills` before the scan to get them. | The harness never writes through a link and never overwrites content that the target owns. |
| 3. Keep out of scope | The scope walk excludes `.vvaharness`; the read tools exempt it from the inventory jail. On `sdk` and `openai`, a repo-wide `Grep` skips skill files unless its path names `.vvaharness`. | Playbook text holds sink patterns. It must never count as target code. |
| 4. Delete | When the scan returns, fails or is interrupted, the harness deletes the copy, and `.vvaharness` too if the scan created it. A force-killed scan (`kill -9`) cannot delete its copy: remove `<target>/.vvaharness/skills/` before the next scan. | The target tree is the same after the scan as before it. |

| Stage | Skills offered | How the model selects one | Switch |
|---|---|---|---|
| S2 threat model | The primary tool-using session. Replay and JSON-repair calls are tool-free and get none. | The skill list (name and description) is the only pointer. The S2 prompt does not name skills. | `step2.skills` (default `true`) |
| S4 deep dive | Every investigation-unit session. | The system prompt names all skills and their path. It says to read at most one lens, only when neither the prompt nor `CweGuidance` gives the family's false-positive checks, and to name the skill in the rationale. The absence method and sibling sweep are already in the prompt. | `step4.skills` (default `true`) |
| Every other stage | None of the packaged detection skills. S6 uses fixed prompt fragments; S11 ships its own `validation-scoring` skill in its staged workspace. | — | — |

Only `deepagents` lists the skills natively: every session and sub-agent sees
each name and description, and reads a body on demand. On other routes S4 can
still open a skill through the path in its prompt, but S2 has no pointer, so use
a `deepagents` role when skills matter. The plain `via: cli` leg WARNs once that
it forwards neither the skill root nor the shell.

> **Probes need a shell, and every shipped profile turns it off.** A probe runs
> only with `step2.bash` or `step4.bash` set to `true` on a route that grants a
> shell: `deepagents` (adds `execute`) or the `cli` tool bridge when `Bash` is
> also in `allowed_tools`; `sdk` and `openai` never grant one (see
> [security.md](security.md)). Shell commands are not path-jailed, so keep
> `bash: false` unless you trust the target. With the shell off, the lens text
> still applies and the model searches with `Grep`.

## Skill catalog

`vvaharness.skills.skill_names()` returns the packaged set. "When it is
selected" paraphrases the trigger in the skill's description where it states
one, else the body. ✓ means the skill ships a `probe.sh`.

| Skill | Kind | What it looks for or does | When it is selected | Probe | Stages |
|---|---|---|---|---|---|
| `access-control` | lens | IDOR/BOLA, missing or wrong authorization, horizontal and vertical privilege escalation, multi-tenant isolation bypass. | The unit decides who may read or change a record: object IDs from a request, role checks, tenant scoping. | | S2, S4 |
| `batch-etl` | lens | Unvalidated bulk input, injection through generated statements, trust in data that an upstream job wrote. | Batch or ETL paths: bulk files, scheduled jobs, generated SQL. | | S2, S4 |
| `client-side` | lens | DOM XSS, secrets and build-inlined env in bundles, tokens in `localStorage`, `postMessage` with no origin check, prototype pollution, security decisions made only in the frontend. | `frontend/`, `public/`, `static/`, `src/components/`, bundler config, or `.js`/`.jsx`/`.ts`/`.tsx`/`.vue`/`.svelte`/`.html` files. | ✓ | S2, S4 |
| `code-exploration` | method | A written inventory of the whole tree, grouped by directory, that accounts for every file (templates, container and CI config, migrations) and reports coverage gaps. | First, when the session must map a repository, find entry points, decide scope, or conclude that something is absent. | ✓ | S2, S4 |
| `crypto` | lens | Weak hashes and ciphers, unsalted password storage, predictable randomness, bad key or IV handling, disabled certificate verification. | The code hashes, encrypts, signs, makes tokens or opens TLS connections. | | S2, S4 |
| `csrf` | lens | State-changing requests without a verified CSRF token, unsafe `SameSite`, CORS that trusts a reflected origin with credentials. | State-changing routes, cookies or CORS settings. | | S2, S4 |
| `deserialization` | lens | `pickle`, `yaml.load`, native object streams, and decoders that create attacker-chosen classes. | Untrusted bytes become objects. | | S2, S4 |
| `hardcoded-creds` | lens | Credentials, keys, tokens and signing secrets in source, config, manifests or deployment files. | Config, constants or deployment files. | | S2, S4 |
| `iac` | lens | Over-permissive IAM, exposed services, container escape, secrets in manifests, unpinned supply chain, disabled controls. | Terraform, Dockerfiles, Kubernetes/Helm, compose, CloudFormation, Ansible or CI pipelines. | ✓ | S2, S4 |
| `injection` | lens | SQL, NoSQL, OS command, LDAP, XPath, XXE, CRLF, SSTI, open redirect, path traversal, SSRF, server-emitted XSS and ReDoS, under a source/sink/no-defence gate. | A request value can reach a query, shell, interpreter, parser or file path. | ✓ | S2, S4 |
| `log-injection` | lens | Forged log records, injected control characters, sensitive values written to logs. | Request values reach log calls. | | S2, S4 |
| `logic-bug` | lens | Missing validation on amounts and quantities, races and TOCTOU, workflow steps that can be skipped or replayed. | Money or quantities, or multi-step or concurrent workflows. | | S2, S4 |
| `missing-controls` | lens | Absent controls (rate limit, session invalidation, cookie flags, debug off, protected secrets or PII), checked at every site where the control belongs. | The claim is that a control is missing. | ✓ | S2, S4 |
| `sensitive-data` | lens | PII, credentials or internals in responses, logs, error pages, templates, caches, headers or debug routes, or stored unprotected. No injection path is needed. | The unit returns, logs, caches or stores data that can be sensitive. | ✓ | S2, S4 |
| `sibling-instances` | method | After a confirmed weakness, greps the whole repository with two or three phrasings of the same pattern and judges each hit on its own evidence. | Only after a confirmation. Never for a refuted or speculative class. | | S2, S4 |
| `ssrf` | lens | Outbound fetches whose URL, scheme, host or port comes from a request (CWE-918). | Avatar-by-URL, webhooks, URL previews, render-to-PDF, import-from-URL, feed ingest, OAuth discovery, "test connection" probes, proxy passthrough, or fetch helpers whose bodies are not visible. | ✓ | S2, S4 |
| `templates` | lens | Stored and reflected XSS in server-rendered templates of every dialect, context-confusion bugs, SSTI, template-layer disclosure, forms with no CSRF token. Anchors the finding on the template line. | `templates/`, `views/`, template files, or a render call. | ✓ | S2, S4 |

## Threat-model baselines (S2)

A baseline is a fixed list of threat categories that S2 must dispose of. S2
classifies the repository into one or more kinds from files, manifests and
entry points (`vvaharness/rules/repo_kinds.py`), so two scans of the same tree
get the same **minimum baseline** block: every item for every kind found.

| Kind | Chosen when | Baseline items |
|---|---|---|
| `web-api` | A network or framework entry point exists, an API artefact exists, or a manifest names a web framework (unless the tree holds only templates). | 10: OWASP A01, A02, A03, A04, A05, A07, A08, A10, XSS, CSRF |
| `web-template` | The tree holds templates and no other source language, and `web-api` does not apply. | 4: unescaped output XSS, SSTI, forms without CSRF tokens, secrets in markup |
| `mobile` | `AndroidManifest.xml`, `Info.plist` or `Podfile` exists, or a manifest names `com.android`. | 5: OWASP Mobile M1, M3, M5, M8, M9 |
| `iac` | A Terraform, container, compose or CI file exists, or Kubernetes/Helm, CloudFormation or Ansible YAML sits under its conventional directory (`k8s/`, `helm/`, `cfn/`, `ansible/`, `playbooks/` and the like). | 5: IAM/RBAC, network exposure, secrets, privileged containers, TLS and storage encryption |
| `native` | C, C++, Rust or Objective-C is present. | 6: CWE-119/787, 416, 190, 134, 362, 78 |
| `library` | None of the kinds above applies. | 4: injection, unsafe deserialization, path traversal, ReDoS |

- **Every item needs a disposition**: a threat whose evidence starts with
  `baseline: <ID>`, or an `open_questions` entry that starts with `<ID>: `.
  S2 sees structure, not code, so silence is not evidence of absence.
- **The audit runs before the threat cap**, because baseline threats often rank
  last and would be cut first.
- **Undisposed items are visible** in Pipeline Diagnostics and the S2 error
  record `baseline_items_undisposed`, so a gap never looks like full coverage.

`step2.baseline` is `auto` (classify, the default), `owasp` (always the
`web-api` list) or `none`.

## CWE knowledge and prompt fragments

| Source | Stage | What it gives |
|---|---|---|
| CWE pairs in the system prompt | S4 | Weaknesses that occur together at one location (for example missing `HttpOnly` with missing `Secure`), and the most specific CWE to report. Inline in the cached prefix, so no tool call. |
| `CweGuidance` tool | S4 | One entry (sources, sinks, sanitizers, non-sanitizers, false-positive checks) from the CWE knowledge base `vvaharness/rules/generic.kb.yaml` (24 distinct CWEs). `step4.cwe_tools` turns it on; `step4.cwe_tool_budget` caps calls per session. The prompt says to call it only for a CWE that the pairs do not cover. |
| `EXCLUSION_RULES` | S6 | Out-of-scope rules A–F: no real attacker, no security impact, wrong layer, handled elsewhere, noise floor, and the rule that an intentionally vulnerable target is still scanned at full strength. |
| Absence method | S4 | Enumerate every site where a control belongs before you call it missing. |
| Shell duty | S2, S4 | Narrow, read-only shell and probe use. Present only when the stage's `bash` key is `true`. |

## Language classification

Language data decides which files count as source and which detectors run. It
does not select a skill. The code graph is a separate parser set (17 languages).

| Table (`vvaharness/lang/detect.py`) | Content | Effect |
|---|---|---|
| `EXT_TO_LANG` | 134 extensions → 42 language keys (`web-template` is one). | S0 detects languages. S1 takes the most common one as primary when the code graph gives none, and vetoes any automatic exclusion that drops a whole language extension. S2 lists them and derives the `native` and `web-template` kinds. S3 tags each unit, most common first. S5 runs each detector only on its languages (`python`, `javascript`, `typescript`, `web-template`). |
| `LANG_DISPLAY` | 47 display names: the 42 keys plus 5 that content or path sniffing finds (`ansible`, `dockerfile`, `github-actions`, `jenkins`, `kubernetes`). | Names languages in output. |
| `VVAH_LANGUAGES` | 6 names: `python`, `java`, `javascript`, `typescript`, `go`, `csharp`. | The `step0.languages` allowlist accepts these and their aliases without a warning. |

## Adding or changing a skill

A skill change is a change to the product source: maintainers make it, and it
ships in a release. To ask for a new skill, file a feature request.

1. **Create `vvaharness/skills/<name>/SKILL.md`.** Keep the lowercase, single-hyphen
   directory name equal to the frontmatter `name`; the loader warns on a mismatch.
2. **Write the description as the trigger**: the family and the code shapes
   that should open it, under 1024 characters (the skills loader truncates a
   longer one on `via: deepagents`).
3. **Write the body for a hard gate**: finding criteria, real sanitizers, traps.
4. **Add a probe only for a greppable family**: POSIX `sh`, read-only, `grep` (not `rg`),
   labelled sections. Name it in `SKILL.md` as `sh .vvaharness/skills/<name>/probe.sh`.
5. **Register the name** in the S4 list in `vvaharness/pipeline/stages/s4/prompts.py`.
6. **Ship it.** `pyproject.toml` packages only `skills/*/SKILL.md` and `skills/*/probe.sh`.

Check that the name is listed and the probe exits cleanly and writes nothing:

```bash
uv run python -c "from vvaharness import skills; print(skills.skill_names())"
sh vvaharness/skills/<name>/probe.sh path/to/sample-repo
uv run --extra dev pytest tests/test_packaging.py tests/test_skill_lifecycle.py tests/test_skill_coverage.py -k "skill or runtime_asset" -q
```

> [!TIP]
> Change a lens to fix a recurring false positive or a missed class that you can
> show in code. A longer body costs tokens on every later turn of each session
> that opens it.

## Limitations

| Limitation | Effect | What to do |
|---|---|---|
| The model chooses the lens. | Two runs can open different lenses for the same unit. The at-most-one rule is a prompt instruction, not a counted budget. | Read the S4 rationale. It names the skill used. |
| Skills are English playbooks for common ecosystems. | A family or framework outside a lens gets the general S4 method and `CweGuidance`, but no specialist traps. | Add or extend a lens. |
| Repository kinds come from file and manifest signals. | An unusual layout can get the fallback `library` baseline. | Read "Repository kind(s) detected" in Pipeline Diagnostics. Set `step2.baseline: owasp` in a `config.local.yaml` overlay ([USER_GUIDE.md](USER_GUIDE.md#5-configuration)) for a missed web service (it uses only the `web-api` list). |

## Further reading

- [architecture.md](architecture.md) — stages, routes, trust boundaries and outputs.
- [models.md](models.md) — routes and model roles.
- [USER_GUIDE.md](USER_GUIDE.md) — `step2` and `step4` keys and profiles.
- [security.md](security.md) — the shell posture and tool jail.
- [AGENTS.md](../AGENTS.md) — the operating manual.
