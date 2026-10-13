---
name: "logic-bug"
description: "Find business-logic defects: missing validation on amounts and quantities, race conditions and TOCTOU, workflow steps that can be skipped or replayed."
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

# Logic Bug Lens

You are reviewing for behavioural / state-machine defects — the class of bug
that has no single grep signature and only surfaces when you reason about
ordering, concurrency, and edge-case inputs.

HARD GATE — for every finding you MUST cite the exact trust boundary that is
crossed: the file:line where untrusted/external input enters, and the file:line
where the security decision is made on that input. If both sides are internal
(service-to-service, same trust domain, idempotent retry, intentional design),
DROP the finding. No trust-boundary citation → no finding.

Reason about behaviour, don't pattern-match. Seed questions:
- Check-then-act windows: between the permission/ownership/balance check and
  the mutation, can a second request, another thread, or a filesystem actor
  change what was checked?
- Auth/session state: what does the login or step-up flow do on empty, null,
  duplicated, or out-of-order messages? Can two concurrent requests against
  one session leave it half-authenticated?
- Numeric identity and counters: what happens at overflow, at zero, at
  negative after a narrowing cast? Does an ID truncated to 32-bit collide
  with a privileged record?
- Connection/protocol state: can a malformed or truncated message leave the
  parser mid-state so the NEXT request on the same connection is
  misinterpreted?
- Caches and memoised decisions: is the cache key missing the
  tenant/user/role dimension, so one principal's result is served to
  another? Does a cached "authorised" decision outlive a revocation?
- Sentinel return values: is the result of indexOf/find/search (which returns
  -1 / null when the token is absent) used as an offset or length WITHOUT the
  `== -1` guard, so "not found" silently becomes position 0 or a wrong
  substring slice? Same for parseInt→NaN or a lookup returning null treated as
  success.
