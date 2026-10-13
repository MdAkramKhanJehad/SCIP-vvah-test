---
name: "iac"
description: "Find infrastructure-as-code and deployment misconfiguration in Terraform, Dockerfiles, Kubernetes/Helm, compose, CloudFormation, Ansible, and CI pipelines: over-permissive IAM, exposed services, container escape, secrets in manifests, unpinned supply chain, disabled controls. Ships probe.sh, which inventories the platforms present and greps each one's known-bad directives."
---

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

# Iac Lens

Hunt misconfigurations that expose data, escalate privilege, or let an attacker
inject code into the build or deploy pipeline.

HARD GATE — every finding MUST cite the specific resource block, step, or
directive (file:line) AND the security property it violates: least privilege,
network isolation, supply-chain integrity, or secret hygiene. A best-practice
item with no concrete attack path is LOW. Vendor-default settings that match
the platform baseline are NOT findings.

## Probe first

`sh .vvaharness/skills/iac/probe.sh [root]` — a MANIFEST INVENTORY naming which
platforms actually exist here, then labelled `file:line` sections of known-bad
directives per platform, plus cross-cutting TLS and credential literals.

Read the inventory first. An absent platform is not a finding — do not report
Kubernetes hardening for a repo with no manifests.

## Polarity: some sections are findings when EMPTY

The probe lists presence for controls whose *absence* is the defect. Invert
these deliberately — `(none)` here is the finding, not a clean result:

- **`every USER directive`** — no image drops root.
- **`securityContext` / `readOnlyRootFilesystem`** — containers run unconstrained.
- **`NetworkPolicy`** — flat pod network; one compromised pod reaches every service.
- **`audit / logging config`** — no trail exists to detect abuse.
- **`cross-account trust`** — hits *without* a matching `ExternalId` in the same
  policy are the confused-deputy case.

## Judgement the grep cannot make

- **CI trust boundary is a conjunction.** `pull_request_target` alone is fine.
  It is RCE with repo secrets only when the workflow *also* checks out the PR
  head ref *and* executes something from that checkout (install, build, test,
  lint). Verify all three in one workflow before reporting.
- **Event data is attacker-authored.** Issue and PR titles, branch names, commit
  messages, bodies. `${{ github.event.* }}` inside `run:` is shell injection;
  the same expression in an `if:`, or passed via `env:` and quoted, is not.
- **A `secrets.*` reference is not a finding.** Every workflow that deploys
  anything reads one, so `secrets reaching a step` is the sweep's
  highest-volume label. It becomes a finding on one of two conditions: the step
  it reaches executes untrusted code, or the secret is written into `env:` /
  `outputs` where a later step logs it. A secret passed straight to a
  SHA-pinned action is neither.
- **Self-hosted runners need both qualifiers.** The finding is a self-hosted
  runner on a **public** repo **without** per-job isolation (fresh VM or
  container per job) — a fork PR then runs on infrastructure that keeps state
  between jobs. On a private repo, or with ephemeral runners, `runs-on:
  self-hosted` is ordinary configuration.
- **GitLab `rules:` can route around approval.** A `rules:` / `only:` /
  `except:` clause that lets a deploy or release job run on a branch the
  approval gate does not cover is an authorization bypass, not a hygiene nit.
  Read which branches the gate protects before judging.
- **Ansible Vault is only as good as where the key lives.** `$ANSIBLE_VAULT;`
  material in the repo is correct practice — it is a credential exposure when
  the vault password or key file is committed alongside it, since anyone with
  the repo can then decrypt. Check both probe labels together.
- **Base-image pinning.** Judge each `FROM`: a digest is pinned, `:latest` or a
  bare name is not, a moving minor tag is a prod-only supply-chain risk.
- **Kubernetes `data:` is base64, not encryption.** Material under `data:` or
  `stringData:` is a committed secret; a sealed-secret or external-secrets
  reference is not.
- **Placeholders are not literals.** `${var}`, `{{ .Values.x }}`, `$(VAR)` in a
  credential position are indirection — but check the committed `values.yaml` /
  `*.tfvars` defaults they resolve to.
- **Environment decides severity.** A public bucket, or `0.0.0.0/0` on
  22/3389/3306/5432/6379/9200/27017, in prod is HIGH; a missing log-retention
  setting on a dev account is LOW.

Give every finding a concrete remediation: the exact directive to add or remove.
