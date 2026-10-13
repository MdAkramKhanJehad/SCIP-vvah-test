---
name: templates
description: "View-layer lens: stored and reflected XSS in server-rendered templates of every dialect (Jinja2 |safe / autoescape false / safe_columns, Django mark_safe, Handlebars {{{ }}}, ERB raw / html_safe, Thymeleaf th:utext, JSP <%= %>, Vue v-html, React dangerouslySetInnerHTML, Razor @Html.Raw, Go text/template), context-confusion bugs in href / src / onclick / <script> interpolations, SSTI from runtime-built template source, template-layer information disclosure, and state-changing forms rendered with no CSRF token. Activate whenever the repo holds templates/, views/, *.html, *.j2, *.erb, *.hbs, *.jsp, *.cshtml, *.vue, or a render_template / render / res.render call."
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

# Template and View-Layer Lens

Templates are not call-graph nodes: `GraphSinksInCommunity` and `GraphNeighbors` never return one,
so `routes/` and `models/` show you the route that *renders* a template, never the template that
*emits* the value. **A template file is a finding LOCATION** — anchor the finding on the template
line that emits the value, not on the handler line that renders the template. The fix edits the
template.

## First move

Run `sh .vvaharness/skills/templates/probe.sh` — one read-only pass over every dialect: view-tree
inventory, labelled `path:line` hits for the whole sink battery, and a per-`<form>` verdict on
whether a CSRF token field sits inside it.

Read the layouts and partials it lists **before any leaf page**: one bad interpolation in
`base.html` or `fragments/*.html` renders on every page that extends or includes it — highest
multiplier in the repo, and the file nobody opens. The probe gives candidates; the judgement below
is not greppable.

## Hard gate — all four

1. **A template sink** — safe/raw marker, autoescape off, a macro kwarg marking a *column* safe, or
   a context HTML-escaping misses.
2. **A value that is not a template-local constant.** Request field, DB column, filename, exception
   object: source. Helper: not. Read *Emptied expressions* before refuting here.
3. **A named path from an external actor.** Stored: name the writing handler and the column.
   Reflected: name the request field and the `render_template(...)` kwarg carrying it.
4. **No context-correct escaper between them** — no sanitizer, no scheme allow-list for URL context,
   no `|tojson` for script context.

## Context is not one context

Escaping `< > & " '` defends the HTML *body* only. Judge by the bytes around the interpolation, not
by the filter.

- **URL** — `javascript:` and `data:image/svg+xml;base64,…` (SVG runs script inside
  `<object>`/`<embed>`/`<iframe>`) hold no HTML metacharacters, so autoescape passes them through
  untouched. Needs a scheme allow-list, not escaping.
- **Event handler** — the attribute body is JavaScript, and the HTML parser un-escapes entities
  before the JS parser sees them.
- **Script** — needs `|tojson` / `json_script` / `template.JS`; `</script>` inside a quoted JS
  string still ends the block.
- **Unquoted attribute** — `class={{u}}`: a space starts `onmouseover=…`. **CSS** — `style` and
  `<style>` bodies.

## Emptied expressions are still sinks

Refusing a blanked or stubbed sink is how this class gets missed. A helper stubbed to return `""`
"for SAST compatibility" still sits in live markup fed by a live column: when markup, column and
writing handler all exist, report the template line even though today's expression is constant, and
name the column the stub stands in for.

## The stored path: sink and source are in different files

The template reads a column an earlier request wrote; neither file mentions the other.

1. Take the interpolated expression (`note.text`, the `safe_columns` entry).
2. Grep the view kwarg: `render_template('home.html'` → the route; the kwarg → the query.
3. Grep the model attribute and every write to it. `GraphImporters` on the model module and on the
   query helper enumerates its readers and writers; the writers are your sources.
4. Check who reads it back. `or_(Note.user_id == user_id, Note.private == False)` renders attacker
   rows in *other* users' pages — cross-account stored XSS, not self-XSS. Say which.
5. Report at the template line, citing the writer's file:line.

## Two more classes at these same lines

- **Information disclosure**, separate from any XSS on the line. Exception or debug objects
  rendered: CWE-209, cause in the handler, location at the template line. Config, secret keys,
  password columns, absolute paths, SQL text, version banners: CWE-200 / CWE-540. Hidden is not
  secret — `hidden` and `password` input values and `data-` attributes all ship, and
  `<!-- HTML comments -->` reach the client where `{# … #}` does not.
- **Missing CSRF token**, CWE-352 **at the `<form>` tag**: template finding, template fix. Take the
  probe's per-form verdict, then cover `fetch` / `axios` / `$.ajax` POSTs in `<script>` blocks
  yourself. Zero CSRF machinery repo-wide plus forms subclassing `wtforms.Form` rather than
  `flask_wtf.FlaskForm` makes **every** state-changing form a finding; unused `Flask-WTF` in
  `requirements.txt` is not a defence. Handler-side judgement is the `csrf` lens;
  `CweGuidance('CWE-352')` has the class detail.

## FP checks — what refutes the finding

- **Autoescape on, no safe marker, HTML-body or quoted-attribute context.** Jinja under Flask
  escapes `"` to `&#34;`, so a quoted attribute holding a plain column is defended. Say why.
- **Helper or bounded expression** — `url_for`, `strftime`, an integer PK, a closed enum, a
  two-value ternary. Does **not** cover a stubbed helper backed by a live column.
- **Re-escaped at the outer interpolation.** `render_template_string()` returns `str`, not `Markup`,
  so `<p>{{ msg }}</p>` escapes what the handler built: XSS refuted, SSTI (CWE-1336) not.
- **A sanitizer on the write path** — name it and its line. A rich-text editor is not one: CKEditor
  / TinyMCE / Quill sanitize in the browser and constrain nothing the POST handler accepts.
- **CSP** without `unsafe-inline`, plus a nonce, lowers severity; it does not refute URL- or
  attribute-context injection. State what it blocks.
- **Not rendered** — under `static/`, a fixture, or absent from the probe's render call sites.

## Enumeration rule

Every interpolation is its own finding; never one "templates do not escape output" finding.

- Open every template the probe's inventory lists, partials included. Do not sample.
- One finding per template file **and** line span. The same column rendered unsafe in three
  templates is three findings: each is edited separately, and a blanket finding can only be
  credited, tracked or fixed once.
- One line can carry two classes: CWE-79 at `{{ x | safe }}` and CWE-200 because the field should
  not reach the page at all. Split reflected from stored at one sink too — different paths,
  different fixes.
- State the sweep: templates globbed, interpolations judged, confirmed, autoescape-refuted.
