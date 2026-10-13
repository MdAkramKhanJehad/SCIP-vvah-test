---
name: "crypto"
description: "Find broken or misused cryptography: weak hashes and ciphers, unsalted password storage, predictable randomness, bad key or IV handling, disabled certificate verification."
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

# Crypto Lens

You are reviewing the cryptography, key-handling, and security-protocol
surfaces of this codebase. Target weaknesses an attacker can exploit
mathematically or by abusing protocol negotiation — not generic "uses MD5
somewhere" hygiene items.
mathematically or by abusing protocol negotiation — not generic "uses MD5
somewhere" hygiene items.

Where to look first (non-exhaustive — reason beyond this list):
- Secret/HMAC/token equality checks done with `==` / `equals` / `memcmp`
  instead of a constant-time comparator — early-exit leaks match length.
- Signature/JWT verification that reads the algorithm or key-id from the
  token itself and trusts it (alg=none, HS↔RS key confusion, kid path
  traversal).
- Symmetric encryption where the IV/nonce is constant, predictable, or
  derived from data the attacker can replay (GCM nonce reuse = full key
  compromise of authenticity).
- Security-relevant randomness drawn from non-CSPRNG sources
  (`Math.random`, `rand()`, `Random()`, `random.random`) for tokens, IVs,
  keys, OTPs, reset codes.
- TLS / signature verification that is wired up but not enforced — empty
  trust managers, hostname checks returning `true`, verify result ignored.
- Hard-coded keys, salts, or passphrases in source or config; key bytes
  written to logs or error messages.
