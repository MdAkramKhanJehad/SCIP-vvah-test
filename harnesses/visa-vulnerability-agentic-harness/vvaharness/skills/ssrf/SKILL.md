---
name: ssrf
description: Hunt Server-Side Request Forgery (CWE-918) — any outbound fetch whose URL, scheme, host or port derives from a request. Activate on avatar-by-URL, webhook/callback registration, URL preview/unfurl, render-to-PDF/screenshot/thumbnailer, import-from-URL, feed ingest, OAuth redirect_uri/jwks_uri discovery, "test connection" probes, proxy and media passthrough, and on helpers named download/fetch/get_image/get_base64_image_blob/load_url whose bodies you cannot see. Ships probe.sh, which greps fetch sinks across seven ecosystems, url-parameter contracts, their call sites and allow-list posture in one pass. Keywords SSRF, requests.get, urlopen, httpx, fetch, axios, OkHttp, curl_exec, 169.254.169.254, cloud metadata, gopher://, allow_redirects, DNS rebinding, blind SSRF, URLField.
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

# SSRF Lens

The application is the attacker's HTTP client: inside the perimeter, holding an instance role.

HARD GATE — all three, or no finding:
  (a) SINK — a call doing network I/O to a URL, host or port, OR a function whose contract is to
      fetch a URL (parameter `url`/`uri`/`src`/`endpoint`/`callback`, or name in
      download/fetch/get_*/import_*/render_*) even when its body is stubbed, vendored or unseen;
  (b) SOURCE — the URL derives from a request-controlled channel (query, form, JSON body, header,
      path segment, webhook registration, uploaded document) or a DB column an untrusted party
      wrote earlier (second-order);
  (c) NO allow-list of scheme AND host enforced on the address actually connected to.
Literal URL, or one only settable through deployment config: DROP.

## Run the probe first

`sh .vvaharness/skills/ssrf/probe.sh` (optional arg: subtree) prints labelled path:line hits for
fetch sinks in all seven ecosystems, indirect mechanisms (XXE, headless render, image coders,
`dblink`), url-parameter contracts AND their call sites, request sources, allow-list and redirect
posture, and — only when a sink exists — reference tables of internal targets, admin ports,
schemes, redirect defaults, rebinding races and deny-list bypasses to cite. An empty ecosystem
section means the repo does not use it; empty sink sections do NOT end the hunt. Trace helpers to
callers with GraphImporters and GraphNeighbors.

## THE SHAPE WE MISS MOST — an opaque fetch helper

A route hands a request-supplied URL to a local helper whose body holds no greppable HTTP call: a
stub, a thin wrapper, a vendored module, a C extension. The `url` PARAMETER is the sink. Measured
instance: a route assigned `get_base64_image_blob(form.url.data)` out of `ImageForm(request.form)`
where the helper module was nine lines of stubs returning empty literals, with no HTTP client
imported anywhere and none in `requirements.txt`. Nothing text-matches: the fetch IS the contract
of the parameter. Never refute on "the body makes no request", "the helper is a stub" or "no HTTP
library is installed". Same repo's fake defence: WTForms `URLField('url',
[validators.DataRequired()])` is a widget plus a non-emptiness check — no scheme, host or
resolution — and the template posted free-text `<input type="text" name="url">`.
ANCHOR the span on the route's call site; when only the helper's contract is in evidence, anchor
its `def` line and name the calling route.

## What still counts

Blind — status, latency, byte count or error text only — is SSRF: port scanning, reachability
mapping, `gopher://` POST-shaped effects. Say which channel the attacker observes. A fetched body
written to a column no template reads back is still a finding; never refute because the response
is discarded, but grep for a reader — if it is re-served, severity rises, so say so. Name the
internal target you reach. A host check that resolves once, or a deny-list of private literals,
does not hold: cite the per-hop redirect rule, the rebinding race, one bypass string.

## FP CHECKS — what genuinely refutes this

Refute, saying which applies, on: an allow-list of BOTH scheme and host enforced against the
RESOLVED address (resolve, reject non-public or non-listed IPs, connect to that pinned address,
redirects re-checked per hop or disabled); egress through a destination-restricting proxy or
gateway configured IN THIS REPO, or an SSRF-hardened client; a hardcoded URL, or a fixed base
where input fills only a path or query segment and cannot change host, port or scheme (path
traversal or parameter injection, another class); a URL from trusted deployment config and no
request field — unless a handler can write that config value. NOT refutations: scheme-only checks,
a host check on the unresolved string, and syntax validators (`validators.URL()`, `URLField`,
`new URL(s)`, `^https?://`) — they constrain the string, not the destination.

## ENUMERATION RULE (CRITICAL — do not skip)

One finding per distinct sink site. Two routes calling the same fetch helper are TWO findings,
each anchored at its own span — each has its own source, reachability and guard. The helper is a
third only if independently reachable; an exported fetch helper with no caller in the repo is a
library entry point, reported separately or not at all, never merged into a route's finding. Never
collapse sites into "URL input is not validated", and report SSRF separately from any other class
at the same lines (open redirect, path traversal, XXE) — different fixes.

CWE, exactly one: 918 by default; 611 when an XML parser's external entity is the fetch mechanism;
441 when the endpoint exists to relay arbitrary requests. 601 is open redirect, never a
substitute. Call CweGuidance for your id.
