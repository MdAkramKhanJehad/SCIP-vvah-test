---
name: sibling-instances
description: After confirming a weakness, sweep the repository for every other site of the same pattern and report each one — a class confirmed at one location is almost never present at only one location.
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

# Sibling-Instance Sweep

A weakness class is a property of how the codebase was written, not of one line. The
developer who interpolated a value into SQL once did it wherever they wrote SQL; the one
who reached for MD5 reached for it in every hashing path. So once you have **confirmed** a
class at one site, the question is no longer "is this a bug" — it is **"where else?"**

Reporting one instance of a repeated defect is a partial answer that reads like a complete
one. The person who applies your fix patches the site you named and ships the rest.

## When this applies

Only **after** a confirmation. Do not sweep for a class you just refuted, and do not sweep
speculatively for classes you have no evidence of — that is how precision dies.

## The sweep

1. **Name the pattern you just confirmed**, concretely enough to search for: the sink call,
   the algorithm name, the decorator that was missing, the flag that was unset.
2. **Grep the whole repository for it.** Not the file you were given, not the directory —
   the repository. Use two or three phrasings, because the same defect rarely looks
   identical twice: `hashlib.md5` and `md5(`; `f"SELECT` and `"SELECT " +` and
   `.format(` near `execute`; `set_cookie(` with and without keyword arguments.
3. **Open every hit and judge it on its own evidence.** A hit is a candidate, not a finding.
   The same call in a test fixture, behind a different guard, or on a value that is a fixed
   literal is a different situation and may be fine.
4. **Report one finding per confirmed site**, each with its own file and its own line span
   pointing at the construct a fix would edit. Do not fold five sites into one finding with
   five paths in the description — each site needs its own anchor to be actionable, and a
   single blanket finding can only ever be credited, tracked or fixed once.
5. **Do not pad.** Near-identical findings at the *same* construct are duplicates, not
   breadth. One per distinct site.

## Patterns that recur, from most to least reliably

- **Query construction.** One interpolated query means the whole data-access layer is
  suspect. Check every `execute` / `query` / `raw` call, including ones in different
  modules from the one you started in.
- **Hashing and randomness.** A weak hash or a predictable RNG appears wherever that
  operation is performed — registration *and* login *and* password reset *and* a token
  minter. The classic miss is exactly this: MD5 in the model's `set_password` **and**
  inline in the registration handler.
- **Regex compiled from a pattern with nested quantifiers.** ReDoS lives in every such
  pattern in the file, not the first one.
- **Outbound requests.** One un-allow-listed URL fetch usually means several, often in the
  same helper module, each reachable from a different route.
- **Deserialization.** `yaml.load` / `pickle.loads` / native object streams tend to appear
  in an import path *and* an export path *and* a cache layer.
- **Cookie writes and header setters.** Frequently one per handler, each missing the same
  flags, with a config default that covers none of them.
- **Decorator omissions.** If one handler in a module lacks the guard its siblings have,
  check every handler in that module — and every other module with the same shape.

## The other axis: the same location, a different class

The converse of this sweep, and just as commonly missed. One handler routinely holds
several unrelated weaknesses — a missing authorization check *and* an injection sink *and*
an unflagged cookie *and* a logic flaw on the amount. Before you leave a location you have
already read, ask what *else* is wrong with it, and report each class separately with its
own CWE. Two classes at one line are two findings, not one broad finding.

## Rationale requirement

State what you swept for, how many candidate sites the search returned, and how many you
confirmed. "Grepped `hashlib.md5` across the repo: 2 hits, both confirmed, at the two
password-writing sites I cite below" is the shape of a complete answer — the sweep term, the
hit count, and the confirmed count. A confirmation with no sweep leaves
the reader unable to tell whether the class was isolated or you simply stopped looking.
