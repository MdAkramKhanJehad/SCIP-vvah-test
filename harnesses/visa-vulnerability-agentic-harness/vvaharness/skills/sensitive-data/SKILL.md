---
name: "sensitive-data"
description: "Find sensitive data reaching somewhere it should not: PII, credentials or internals in HTTP responses, logs, error pages, templates, caches, headers, debug routes, or stored unprotected. Point-of-occurrence — no injection path required. Ships probe.sh, which greps every leak channel (debug flags, exception-to-response, log calls on sensitive names, whole-object serialization, weak password storage, cache and HSTS headers, introspection routes, settings constants)."
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

# Sensitive Data Lens

You are a Sensitive-Data-Exposure expert. Hunt places where the application
reveals more than necessary — to the user, to logs, or at rest. These are
point-of-occurrence findings: you do NOT need an injection path. The question
is only "does this output, store, or log contain data an attacker can harvest?"

HARD GATE — a finding requires BOTH:
  (a) genuinely sensitive data: credentials, session tokens, PII (SSN, DOB,
      card PAN, bank account, health record), internal system details (stack
      traces, SQL text, server paths, version strings), or confidential
      business data (pricing, unreleased features), AND
  (b) a channel an attacker reaches or can read: response body, response
      header, error page, log file, temp file, world-readable DB column, URL
      or query string, or an unauthenticated debug endpoint.
Generic `print()` / `console.log()` on non-sensitive variables is NOT a
finding. "We should encrypt this" with no concrete exposure path → LOW.

## Probe first

`sh .vvaharness/skills/sensitive-data/probe.sh [root]` — labelled `file:line`
sections across error/debug exposure, logging, response and serialization
leakage, storage, headers and caching, debug/admin routes, and settings
constants. Every line is a CANDIDATE; apply the gate to each.

## Polarity: three sections are findings when EMPTY

- **`strong KDF present` → `(none)`** and passwords are stored with no
  key-derivation function at all. That is the finding.
- **`Cache-Control / no-store` → `(none)`** on an app serving authenticated
  pages: proxies and browsers cache PII.
- **`Strict-Transport-Security` → `(none)`** on an HTTPS app: downgrade is open.

## Judgement the grep cannot make

- **Look at the template file, not only the view.** A view that *catches* an
  exception and passes the raw message into the render context still leaks it.
  The leak is in the `.html`, where `{{ error }}` / `{{ sql_error }}` /
  `{{ exception }}` prints it. Read both sides before deciding.
- **Serialization needs a field audit.** `to_dict()` / `__dict__` /
  `model_to_dict()` is only a finding when the model actually carries fields
  the caller must not see — `is_admin`, `internal_id`, `token`,
  `hashed_password`. Open the model and check.
- **Settings constants: judge the name, then the value.** The probe lists every
  ALL_CAPS constant holding a non-trivial string literal. Flag the ones whose
  name suggests sensitivity even when they do not follow the framework's
  `SECRET_KEY` convention — `flag`, `secret`, `key`, `token`, `data`,
  `credential`, `password`. A literal like `SENSITIVE_DATA = 'FLAG...'` is a
  finding; `APP_NAME = 'billing-service'` is not.
- **Placeholders and reads are not literals.** `os.environ[...]`,
  `${VAR}`, and vault lookups in a credential position are indirection.
- **Sensitive name is not sensitive content.** A log line mentioning
  `token_count` or a column named `flagged_at` matches the pattern and is
  nothing. Read the value that actually flows.
- **Reachability of a debug route.** `/metrics` or `/health` behind
  authentication or bound to localhost is not exposure. Django admin reachable
  at `/admin/` is not a finding by itself — flag it only when it discloses more
  than expected (user emails, session tokens).
- **Severity follows blast radius.** One user's DOB in a log is MEDIUM; every
  user's PAN in a world-readable file is HIGH.
