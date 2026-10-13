---
name: client-side
description: "Weaknesses in browser-delivered code — JS/TS, JSX/TSX, Vue, Svelte, Angular, HTML, templates, bundler and Docker config. DOM XSS and code-exec sinks, secrets in bundles or config.js, build-inlined REACT_APP_/NEXT_PUBLIC_/VITE_ env, source maps and dev servers shipped in images, tokens in localStorage or non-httpOnly cookies, client-side JWT decoding, postMessage without an origin check, permissive CORS/credentials, unvalidated redirects, prototype pollution, missing SRI, vulnerable package.json pins — and above all security decisions made only in the frontend (disabled buttons, hidden fields, is_admin render gates, a client-computed user_id) that the server never repeats. Ships probe.sh, which greps every sink class in one pass. Activate on frontend/, public/, static/, src/components/, bundler config, or .js/.jsx/.ts/.tsx/.vue/.svelte/.html files."
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

# Client-Side Lens

This code is already the attacker's — on their machine, in DevTools, editable before it runs.
**Nothing shipped to the client is secret**: keys, connection strings, source maps, an inlined
`.env`. **A client-side control is not a security control**: `disabled`, `hidden`, an `is_admin`
render gate, a form schema, a client-computed ID. So **a check that exists only in the frontend
IS the finding** — the defect is the server-side absence it conceals. Nothing upstream hands you
frontend code; go look.

## Run the probe first

`sh .vvaharness/skills/client-side/probe.sh [root]`

Read-only, ~1s. It greps every client-side sink class at once, including the *server* lines that
read client-sent parameters, and skips test, mock, story and example paths, which are not
shipped. Sections are CWE-labelled and print `path:line` or `(none)`. A *missing* section means
the probe broke; `... N hits total` means the cap truncated, so grep that class yourself. It
locates, it decides nothing below.

## HARD GATE — a finding requires ALL of

1. **A construct with a line span** — sink call, storage write, literal secret, listener, build
   key, pin. Not "the SPA should validate input".
2. **A named consequence to an asset** — which credential leaks, which account is acted on, what
   the attacker executes.
3. **For a "the frontend enforces X" claim, the server gap in hand** — the handler trusts the
   client value or omits the check. Unreachable backend: unverified, downgrade, never assert.
4. **Exactly one most-specific CWE**, `CweGuidance`-checked: `innerHTML` XSS is CWE-79 not
   CWE-20, client-enforced authorization CWE-602 not CWE-284, a server trusting a client
   `user_id` CWE-639 not CWE-863.

## Judgement the probe cannot make

- **Client-supplied identity — highest value here.** Client sends `user_id`/`role`/`amount`;
  handler reads `data.get('user_id')` instead of the authenticated principal. CWE-639 **at the
  server line**, client line as evidence. Probe prints both halves; read the handler.
- **Client-side JWT decode is unauthenticated parsing** — a claim used as identity or permission
  trusts a payload the client mints.
- **Build-inlined env is published**; ask only whether the value is secret.
- **Origin checks by `indexOf`/`startsWith`/`endsWith`** pass `https://trusted.evil.com`; only
  strict equality against an allow-list refutes. `postMessage(data,'*')` with a token is CWE-201.
- **A base URL from `window.location.hostname`** sends every `Bearer` where the Host header
  points; with cross-origin `credentials:'include'`, check the server for middleware reflecting
  the request `Origin` with `Allow-Credentials: true` — a full same-origin-policy bypass.
- **In the shipped-artifacts section**: a dev-server `CMD` ships hot reload and source maps
  (CWE-489); `COPY . .` with no `.dockerignore` entry sweeps in `.env`/`.git`; no lockfile beside
  `npm install` means `^` resolved at build time, so what ships is unpinned.
- **Toggles that persist nowhere** (2FA checkbox on `useState`, no request) have no server side
  at all — you see it only by reading the component.
- **A password form with only a new-password field** misses re-authentication (CWE-620).
- `startsWith('/')` does not refute a redirect (`//evil.com` is protocol-relative), and a bound
  only in markup (`step="0.01"`) is no bound — check the handler rejects negatives.

## FP CHECKS — what REFUTES

- **A sanitizer on the path** (probe's sanitizer section); React/Vue/Svelte interpolation escapes
  by default and is **not** a finding.
- **Sink value is a literal or closed enum**; `setTimeout` given a function reference;
  `setAttribute` on a non-URL, non-`on*` attribute.
- **The "secret" is public by design** — the probe flags the known-public prefixes (`pk_live_`,
  Firebase, Sentry DSN, Maps). Name which, and refute.
- **The server repeats the check**: identity from the verified principal, amount re-validated,
  role re-checked. A client-sent id used only as a *lookup target* while the handler derives the
  actor (`sender_id=current_user.id`) is not CWE-639.
- **The pin is patched** — read the version, and name it in the finding.

Say which you checked; an unqualified frontend finding reads as a lint rule.

## ENUMERATION RULE (CRITICAL — do not skip)

One finding per distinct site, with its own file and `line_start..line_end` on the construct a
fix edits.

- Anchor token storage at the **write**, not at every `getItem` — but `token` in storage and
  `refresh_token` in a JS cookie are two findings.
- Every raw-HTML sink occurrence is its own finding: different source, fix, line.
- Every client-supplied-identity request is its own: a password change and a transaction list
  each sending `user_id` are two defects, two handlers.
- Every vulnerable pin is its own finding.
- **The other axis:** one component usually holds several classes at once — token storage,
  client-derived identity, missing re-auth, a cleartext base URL. Before leaving a file, ask what
  else is wrong with it; emit each class with its own CWE.
- Never collapse into "frontend security issues" — a blanket finding is credited once.

## The shape we miss

**A client file is proof that a server-side parameter is attacker-controlled.** `frontend/src/`
went unread in every measured run while a whole authorization-bypass chain sat in it. Read the
client to learn which server parameters to distrust, then report the server line.
