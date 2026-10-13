---
name: injection
description: "Hunt injection classes (SQL, NoSQL, OS command, LDAP, XPath, XXE, CRLF, SSTI, open redirect, path traversal, SSRF, server-emitted XSS, ReDoS) under a source/sink/no-defence hard gate. Ships probe.sh: a per-class sink sweep plus a census of the defences present."
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

# Injection Lens

Find where attacker-controlled input is merged into a downstream interpreter
without separating code from data, across every class named in this skill's
description.

HARD GATE — a finding requires ALL THREE:
  (a) a SINK that interprets its input — SQL executor, shell exec, XML parser,
      HTTP client, response writer, file open, regex compile, template render,
      redirect, header setter,
  (b) a SOURCE reachable from an external actor — request field, message body,
      file upload, CLI arg, env var, or a DB row previously written by an
      untrusted party (second-order),
  (c) NO intervening defence: no parameterisation, no allow-list, no
      context-correct escaper, no library-provided safe wrapper.
If (a)'s argument is a hardcoded literal, or nothing reaches the sink on any
path, DROP it. "We should validate this" with no sink is not a finding here.

## Probe first

`sh .vvaharness/skills/injection/probe.sh [root]` — a labelled `file:line`
section of sink hits per class, then a DEFENCE CENSUS counting the files that
carry each defence. Every line is a CANDIDATE; `(none)` is a real answer, so
stop working that class. The sections are a starting set, not the lens.

## What refutes a candidate

- **Literal argument.** Constant, column name from a fixed tuple, internal enum.
- **Defence in the wrong context.** HTML-escaping a value bound for JS or an
  attribute; `shlex.quote` on the binary but not its args; an allow-list on a
  different variable than the one reaching the sink; `%s` inside the query
  string (interpolation) read as `%s` with a params tuple (binding).
- **Parse-check-use mismatch.** The reverse, and a finding: code parses the URL
  or path to check host/prefix, then builds the request or `open()` from the
  raw string.
- **Second-order flow.** Taint entered on an earlier write — DB row, cache,
  config — later concatenated into a query. The call site looks clean; only
  tracing the write reveals it.
- **XXE flags.** A parser factory is vulnerable only if `disallow-doctype-decl`
  / `FEATURE_SECURE_PROCESSING` / `resolve_entities=False` is absent. The probe
  finds the factory; you check the flag.
- **SSRF allow-list that still permits metadata** — `169.254.169.254`,
  `metadata.google.internal`, `metadata.azure.com`.
- **ReDoS input size.** Catastrophic patterns matter against unbounded input;
  on a length-capped field, LOW.
- **Zip-Slip.** `extractall` counts only with unvalidated member names on an
  attacker-supplied archive.

## ENUMERATION RULE (CRITICAL — do not skip)

Every distinct sink is its own finding, with its own class (SQLi / CMDi /
SSRF / …), file, line, source, and sink. Three raw SQL builders across two
files are three findings; one SSRF plus one path traversal in one handler are
two. Never collapse them into an omnibus "input validation missing" — each sink
has its own exploitability and its own fix location.
