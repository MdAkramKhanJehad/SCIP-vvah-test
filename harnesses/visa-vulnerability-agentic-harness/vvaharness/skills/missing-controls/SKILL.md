---
name: missing-controls
description: Find weaknesses that consist of an ABSENT control — no rate limit, no session invalidation, no cookie flags, debug left on, secrets or PII stored in cleartext — by enumerating every site the control belongs and checking each.
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

# Absent-Control Lens

Every other lens hunts for a dangerous **construct** — a sink, a concatenation, a weak
algorithm. This lens hunts for a **hole**. You cannot grep for a decorator that was never
written, and a deterministic scanner will never hand you a line number for it, so nothing
upstream will point you at these. If you only investigate what you were shown, you will
never report one.

The method is inverted. Instead of "is this construct dangerous?", ask **"what should be
here, and is it?"** That requires enumerating sites first and judging second.

## Hard gate — a finding requires all three

1. **The site is real and reachable.** A concrete handler, route, cookie write, session
   config, or storage write that an external actor can reach. Not a hypothetical.
2. **The control genuinely belongs there.** Name the asset it would protect and the actor
   it would stop. "Every endpoint should have rate limiting" is not analysis; "`/api/login`
   accepts unlimited password guesses against a user-supplied username" is.
3. **It is absent on THIS path**, and you checked — not merely "not visible in the file you
   were given". Middleware, a base class, a decorator factory, a reverse-proxy config, or a
   framework default can supply it somewhere you have not looked yet. Look, then conclude.

If the control exists anywhere on the path, **refute** and say where it is. A refutation
here is a real result: it is how the FP rate stays low.

## Enumerate before you conclude

These are systemic gaps, and a systemic gap is only actionable if the site list is
complete. Reporting one unprotected route while four others are equally exposed means
whoever applies your fix still ships the vulnerability.

So for each control below: **Grep the whole repository for every site of the kind it
protects, then decide site by site.** Report one finding per absent site, each with its own
file and line. If it is present everywhere you enumerated, refute and say how many sites
you checked.

## The controls, and where each belongs

### Anti-automation on credential and cost endpoints — CWE-307, CWE-799
**Sites:** every handler that verifies a credential or consumes a scarce resource — login,
registration, password reset, OTP/MFA verification, token refresh, email send, payment,
file upload, expensive search.
**Present looks like:** `flask-limiter` `@limiter.limit(...)`; `django-ratelimit`
`@ratelimit`; DRF throttle classes; `slowapi` on FastAPI; `express-rate-limit`; Spring
`Bucket4j`; a failed-attempt counter with lockout persisted per account **or** per source;
a CAPTCHA gate; an upstream WAF/gateway rule **only if you can see it in this repo**.
**Note:** a `LoginAttempt` model or a `failed_count` column existing is not the control —
find the code that *reads* it and *refuses*. Storage without enforcement is a decoy.

### Session termination — CWE-613, CWE-384
**Sites:** logout, password change, email change, role change, account deactivation.
**Present looks like:** server-side session destroy (`session.clear()`,
`request.session.flush()`, store delete); for stateless JWT a denylist/`jti` revocation
check, or a `token_version`/`password_changed_at` claim compared on every request.
**The classic hole:** a logout endpoint that returns `200 {"message": "logged out"}` and
nothing else, while the issued JWT stays valid until expiry — the token is still a working
credential. Also: a password change that does not invalidate other live sessions, and a
session with no absolute or idle lifetime at all.

### Cookie and transport flags — CWE-614, CWE-1004, CWE-1275, CWE-319
**Sites:** every `set_cookie` / `Set-Cookie` write **and** every framework session config
key. There are usually more of these than you expect; grep for all of them.
**Present looks like:** `httponly=True`, `secure=True`, `samesite="Lax"` or `"Strict"` on
each write; `SESSION_COOKIE_HTTPONLY` / `_SECURE` / `_SAMESITE`; Django
`SECURE_SSL_REDIRECT`, `SECURE_HSTS_SECONDS`.
**Report per site.** A config-level default does not cover an explicit `set_cookie` that
overrides it, and fixing the config does not fix the explicit writes.

### Deployment and debug posture — CWE-16, CWE-215, CWE-489
**Sites:** app entrypoints, settings modules, Dockerfiles, compose files, CI/CD manifests.
**The holes:** `app.run(debug=True)` — the Werkzeug console is remote code execution, and
`host="0.0.0.0"` makes it reachable; Django `DEBUG = True`; `ALLOWED_HOSTS = ["*"]`;
stack traces or exception detail returned to the client; verbose error handlers;
directory listing; admin or metrics endpoints exposed without auth; default credentials
left in a seed or fixture.
**On CWE choice:** report the class your evidence supports. If debug mode yields arbitrary
code execution, that is what it yields — say so, and name the misconfiguration as the
cause in your description so both readings are recoverable.

### Data at rest and in transit — CWE-312, CWE-311, CWE-319, CWE-359
**Sites:** model/schema definitions, migrations, seed and fixture data, serializers,
cache and queue writes, log statements, backup and export paths.
**The holes:** identifiers and PII (national ID, DOB, full address, card data, health
data) stored as plain columns or plain JSON blobs; a seed/fixture that commits real-looking
sensitive values; secrets written to a cache or queue unencrypted; TLS verification
disabled on an outbound call (`verify=False`, `rejectUnauthorized: false`).
**Distinguish:** stored-in-cleartext (CWE-312) is a different finding from
returned-in-a-response (CWE-359/200) even for the same field. If both hold, both are
findings — they have different fixes and different blast radii.

### Request forgery and origin trust — CWE-352, CWE-942, CWE-1021
Covered in depth by the `csrf` lens; treat it as part of this sweep when the claim is that
a *protection is missing* rather than that a sink is dangerous. **Enumerate every
state-changing handler**, not just the one you were pointed at.

### Authorization
Covered by the `access-control` lens, which already frames it as an absence. Note its
"where to look" examples are Spring/JAX-RS; translate to the framework in front of you —
Flask `@login_required` / `before_request`, Django permission classes and mixins, FastAPI
`Depends(...)`, Express middleware.

## False-positive discipline

Refute, do not report, when:

- The control is present anywhere on the path, including in middleware, a base class, a
  dependency, a decorator applied at the blueprint/router level, or a framework default
  you can point to.
- The endpoint is genuinely public and unauthenticated by design (health check, static
  asset, public docs, webhook with signature verification present) and holds no scarce
  resource.
- The "sensitive" data is obviously synthetic test fixture data **and** the file is not
  shipped or seeded into a running environment. If it *is* seeded, it is a finding.
- The target is a fixed constant rather than attacker-varied — bounded blast radius, do
  not inflate it.

Say which of these you checked. An absence claim with no stated search is indistinguishable
from a guess, and the reader cannot tell them apart.

## What good output looks like

One finding per absent site, each naming the file and the line the fix must edit — the
handler signature or decorator line for a missing guard, the `set_cookie` call for a
missing flag, the settings line for a posture problem. The rationale states what you
enumerated, how many sites you found, which had the control and which did not.
