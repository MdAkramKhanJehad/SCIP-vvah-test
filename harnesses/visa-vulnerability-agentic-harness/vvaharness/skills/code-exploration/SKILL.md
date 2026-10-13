---
name: code-exploration
description: Exhaustive repository exploration procedure — Glob the whole tree into a written inventory, group it by directory, and account for every file including templates, Dockerfiles, compose and k8s manifests, nginx/uwsgi/gunicorn config, CI workflows, dotfiles, SQL migrations, static assets and __init__.py. Load FIRST, before any lens, when you are asked to map a repository, enumerate its attack surface, find entry points, decide what is in scope, or conclude that something is absent. Covers reading paginated files to the last line, following handler-to-template and handler-to-model edges with GraphImporters / GraphNeighbors, and reporting coverage gaps honestly.
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

# Exhaustive Repository Exploration

This is not a vulnerability lens. It is the coverage procedure every lens runs on top of.
A lens pointed at 38% of a repository finds at most 38% of its bugs, and reports that
fraction in the confident tone of a complete answer.

> **About the examples below.** Every path, line number and snippet in this document is an
> *illustration of a shape*, drawn from patterns that recur across web applications. None of
> them is a claim about the repository you are scanning. Never go looking for `app.py` or
> `routes/` because this file mentions them, and never report a finding you have not read in
> the tree in front of you. `Glob` tells you what actually exists; this document only tells
> you where to look and what the answer tends to look like.

## The measured failure

This procedure exists because of a repeated, measured result. On a small Python web
application, an unaided threat-modelling pass could name only **17 paths — 38% of the 44
files it claimed to have accounted for**, while `Glob **/*` returned **45**. **27 files were
invisible** to it: every HTML template, the entry module itself, `Dockerfile`,
`docker-compose.yml`, the nginx and uwsgi config, and every `__init__.py`. On a second
application of 23 files, only **7 paths (30%)** were nameable and an entire `frontend/` tree
of 14 files was never opened.

Those gaps are where findings hide, and the two shapes below are why. Both are invisible to a
`*.py`-only sweep, and both were missed for the same reason: nobody opened the file.

- **A tiny entry module carries the worst of it.** A 34-line module can hold both
  `app.secret_key = "super secret key"` — the key that signs every session cookie — and a 404
  handler that does `render_template_string(f"{error}. Requested URL was {request.path}")`,
  compiling an attacker-controlled request path as a Jinja template. Two classes, two CWEs,
  one file short enough that it reads as boilerplate. The WSGI config
  (`module = app:app` in a `uwsgi.ini`) is what tells you that file is the live entry point.
- **The client names the victim, in a file the backend sweep never opens.** A frontend
  component decodes the JWT it already holds —
  `const userId = JSON.parse(atob(token.split('.')[1])).user_id` — and POSTs that id in the
  request body. The handler then does `user_id = data.get('user_id')` →
  `User.query.get(user_id)` → `user.set_password(...)`, never reading the authenticated
  principal its `@token_required` decorator bound one line earlier. The unread frontend file
  is the proof that the id is client-supplied and trivially swappable; without it the handler
  looks like it is merely trusting its own input.

## HARD GATE — every finding you emit from this pass requires all four

1. **An inventory exists, written down, before any conclusion.** The `Glob` output, grouped by
   directory, with a count. Not "I looked around".
2. **The file was opened and read to its last line.** Not a `Grep` hit with two lines of
   context. Not the first page of a paginated `Read`.
3. **A repo-relative path and a real `line_start..line_end`** copied from the numbered `Read`
   output, plus exactly one most-specific CWE id.
4. **For any absence claim** — no auth, no escaping, no rate limit, no TLS — name the files
   you opened looking for the control. An absence asserted against an unread directory is not
   a finding, it is the shape of one.

## 1. Enumerate before you read

`Glob` first, always, and never start from the file you were handed.

```
**/*            → every path, dotfiles included; this is the inventory
```

Then split the inventory by directory and write the group list down as your plan. The shape of
that plan, for a mid-sized Flask-style application, is a census like:

```
<root> (11)  routes/ (7)  templates/ (9)  templates/partials/ (2)
models/ (5)  forms/ (6)   utils/ (3)      conf/ (1)  static/ (1)     = 45
```

Mark each group open or closed as you go, and make the counts sum to the inventory size. The
sum is the point: a census that does not add up is a census with a directory missing from it.

**Coverage is the set difference between the inventory and the set of files you have opened.**
Compute it explicitly before you stop. If the difference is non-empty you are not done, you
are mid-pass.

Three ways the inventory itself lies, all of which you must check for:

- **`Glob` truncates at 500 hits**, appending `... (N more)`. If you see that line, your
  inventory is a prefix — narrow by subtree (`routes/**`, `frontend/**`) until every group
  returns whole.
- **Scope exclusions are invisible in `Glob` but loud in `Read`.** A path outside the scan
  scope returns `ERROR: path '<p>' is excluded from the scan scope (not in the scanned file
  inventory)`. That is a third state, neither read nor unread — record it as excluded, not as
  clean.
- **Do not substitute a graph node list for the inventory.** The graph walk skips the entire
  dot-namespace — files like `.dockerignore`, `.prettierrc` and `.pylintrc` exist in the tree
  and none is a file node. `Glob` returns them. Glob is the inventory; the graph is an index
  over part of it.

## 2. The file classes a source-only sweep skips

Each of these carries findings and each is invisible to a `*.py` / `*.java` / `*.js` sweep.
Glob them by name.

**Templates and views** — `**/*.html`, `**/*.jinja2`, `**/*.j2`, `**/*.jsx`, `**/*.tsx`,
`**/*.vue`, `**/*.erb`, `**/*.jsp`, `**/*.twig`, `**/*.hbs`, `**/*.ejs`, `**/*.blade.php`.
The escape decision lives here, not in the handler. `Grep` templates for `| safe`,
`safe_columns`, `autoescape false`, `{{{`, `html_safe`, `raw(`, `dangerouslySetInnerHTML`,
`v-html`. That grep is usually short — a handful of lines across the whole template tree —
and each line it returns is a location where escaping was switched off deliberately, in the
form `{{ note.text | safe }}` or `render_table(rows, safe_columns=['text'])`. Short is not the
same as empty: read every hit.

**Container and orchestration** — `Dockerfile*`, `**/Dockerfile`, `docker-compose*.y*ml`,
`**/*.tf`, `**/*.tfvars`, `k8s/**`, `**/*deployment*.y*ml`, `**/values.yaml`,
`**/templates/*.yaml` (Helm), `Procfile`, `uwsgi.ini`, `gunicorn.conf.py`, `**/nginx*.conf`,
`**/conf/*.conf`, `supervisord.conf`, `**/*.service`. These compose into single findings that
no one file states. A reverse-proxy config whose only listener is `listen 80 default_server`
with `uwsgi_pass` behind it and not one `ssl` token in the file; a compose file publishing
`ports: - 5000:80`; a `Dockerfile` whose `CMD` starts that proxy — four files, one cleartext
-transport finding, zero of them `.py`.

**CI/CD** — `.github/**`, `.gitlab-ci.yml`, `Jenkinsfile*`, `azure-pipelines.yml`,
`.circleci/config.yml`, `bitbucket-pipelines.yml`. Read for `pull_request_target`, unpinned
third-party actions, `${{ github.event.* }}` interpolated into `run:`, secrets echoed to logs.

**Dependency manifests** — `requirements*.txt`, `pyproject.toml`, `Pipfile*`, `poetry.lock`,
`package.json`, `*-lock.json`, `yarn.lock`, `pom.xml`, `build.gradle*`, `go.mod`, `Gemfile*`,
`*.csproj`. Unpinned or ancient versions are findings; the manifest is also how you learn
which framework defaults apply.

**Dotfiles and env templates** — `.env*`, `*.env.example`, `.dockerignore`, `.npmrc`,
`.netrc`, `.pylintrc`, `.prettierrc`, `.git-credentials`, `**/.aws/**`. Committed real values
are credential findings, and `.dockerignore` is how you learn what a broad
`COPY . /srv/app` in the `Dockerfile` did *not* exclude from the image.

**SQL and migrations** — `**/*.sql`, `migrations/**`, `alembic/versions/**`, `db_seed.py`,
`**/fixtures/**`, `**/seeds/**`. Seed files ship default credentials into running systems.

**Static assets** — `static/**`, `public/**`, `assets/**`, `**/*.map`. Source maps, API keys
in bundled JS, backup files served by the static handler.

**`__init__.py`, base classes, shared helpers** — `**/__init__.py`, `**/base*.py`,
`**/base_*.py`, `**/middleware*`, `**/conftest.py`, `**/utils/**`. This is where
centrally-applied controls live, and where their absence is centrally fatal. Four shapes to
expect:

- A package `__init__.py` whose entire body is `import routes.<name>` statements inside a
  `def init():` called once from the entry module. **That** is the route registration, so a
  route table reconstructed without it is short every module it names.
- An `__init__.py` that builds the engine — `create_engine('sqlite:///' + ..., echo=True)` —
  logging every SQL statement, including the ones carrying credentials.
- An `__abstract__ = True` base model supplying `id` and `created_at` to every subclass. Read
  it before claiming any model lacks either.
- A base template: one read of it settles a control for every template that `extends` it. If
  its `{% block head %}` holds three `<meta>` tags and none is a `Content-Security-Policy`,
  that is one finding covering the whole tree — and you only know it because you opened the
  parent.

## 3. READ TO THE END

`Read` is paginated — `read(file_path, offset=0, limit=2000)` — and its output is byte-capped,
so a large file returns a **prefix**. A file read halfway produces exactly the same false
"absent" conclusion as a file never read, and produces it with more confidence.

- Watch the tail of every `Read` for `... [truncated]` or
  `…[truncated N chars to fit context — re-read a specific line range with Read offset/limit
  if you need more]`. Either marker means you hold a prefix.
- **Continue from the last line number you were shown.** `offset` is a 0-based line index and
  output is `cat -n` style, so a first page ending at displayed line 2000 continues at
  `offset: 2000`. Repeat until the tail carries no truncation marker.
- **Confirm you reached the end**: a `Read` whose `offset` is past the final line returns
  `(file is empty or offset past EOF)`. That, or a page shorter than `limit` with no truncation
  marker, is the proof the file is finished. Assumption is not proof.
- **One exception, and it is a trap.** The reader only decodes the first 800,000 characters of
  a file and caps each rendered page at 200,000. On a file larger than that, the EOF marker is
  a *false* end-of-file — it means you exhausted the window, not the file. `Grep` the file for
  a construct you expect near its end; if it hits at a line your pages never reached, record
  the file as partially read in your coverage report.
- Narrow with `offset`/`limit` only *after* you have seen the whole file once. `Grep` is for
  locating, never for concluding.

## 4. Follow the edges

The inventory tells you what exists; the edges tell you what a file you just read pulls into
scope. Both are mandatory.

- **A handler that renders a template puts that template in scope.** A handler that builds
  `text(f"text like '%{search_param}%'")` into a query is one finding; the template it then
  renders, marking that same column as `safe_columns=['text']`, is a second one in a different
  file. Read the handler, miss a class; read both, get two findings.
- **A model the handler writes puts that model in scope** — and its base class, its migration,
  and any serializer that returns it.
- **A config key a handler reads puts the config file in scope**; a template that `extends` or
  `include`s another puts the parent in scope.
- **Use the graph with its real signatures; do not guess.**
  `GraphImporters(file)` → the files that import `file`.
  `GraphNeighbors(file, function)` → `{"callers": [...], "callees": [...]}`; it needs BOTH
  arguments, an exact path and an exact function name.
  `GraphCommunityOf(file)` → the module name, which you then hand to
  `GraphSinksInCommunity(community)` for the sinks already known in that cluster.
  `CweGuidance(cwe_id)` once you have a class in hand.
- **An empty graph answer is a signal, not an all-clear.** `GraphImporters` reads module-level
  import edges only. A module imported from inside a function body — the `def init():`
  registration shape above — has no module-level importer, so the graph correctly reports none
  while the module is plainly live. When the graph says a live module has no importer, go read
  the `__init__.py` yourself.
- Graph hits *add to* the inventory-driven sweep, never replace it. Templates, YAML, `.conf`
  and dotfiles are reachable only by `Glob`.

## FP CHECKS — what refutes a finding from this pass

Refute and say so; a refutation with a named search is a result.

- **The control exists somewhere you had not read.** Before claiming a missing guard, open
  `**/__init__.py`, the base class, the blueprint/router registration, `**/middleware*`, and
  the reverse-proxy config. A `before_request`, a decorator applied at blueprint level, or an
  nginx `auth_request` refutes it.
- **The template escapes after all.** Jinja and ERB autoescape by default. Only an explicit
  `| safe`, `safe_columns=`, `autoescape=False`, `{{{`, `raw()`, `html_safe`, `v-html` or
  `dangerouslySetInnerHTML` defeats it. No such marker → no XSS from that render.
- **The file is not shipped.** `.dockerignore` / `.gitignore` excludes it from the image, it
  lives under `tests/`, or it is documentation (`docs/**`, `course/**`, `*.md`). Prose
  describing a vulnerability is not the vulnerability — do not report a write-up of a bug as
  the bug.
- **The config is an example.** `*.example`, `*.sample`, `*.template` with placeholder values
  are not credential leaks. Real-looking values in a live `.env` or a seed script are.
- **The value is a fixed literal**, not attacker-varied.
- **You only read a prefix.** If you cannot state that you reached the last line, the finding
  is not gated yet. Finish the read.

## ENUMERATION RULE

**One finding per distinct site, each with its own file and its own line span.** Three
templates disabling escaping on the same field is three findings, at three template paths,
because each is an independent edit a fix must make.

The same rule survives contact with a noisy grep. Sweeping a weak-hash call across a backend
typically returns a mix you must sort, not a count you can report: a `set_password` that does
`self.password_hash = hashlib.md5(password.encode()).hexdigest()`, the identical expression
inlined into a registration handler in another file, and the verifier that compares against
that same digest. The first two are two independent password-writing sites, so two findings at
two anchors in two files. The third is a hit to judge — it reads the digest rather than
writing it — not a third finding to bank. State which you counted and why.

Never collapse sites into an omnibus "output encoding missing across templates" or "insecure
deployment configuration". A blanket finding can be credited, tracked and fixed exactly once,
so the remaining sites ship. Equally: do not pad — the *same* construct reported twice is a
duplicate, not coverage.

Before leaving a file you have already read, ask what *else* is wrong with it. The entry-module
shape at the top of this document is the reminder: a hardcoded signing key and an SSTI sink can
share one short file. Two classes, two CWEs, two findings, one file you already had open.

## Report coverage honestly

Close the pass with the arithmetic:

- Inventory size, files opened, files read to the end, files refused as out of scope.
- **The named list of what you did not finish, and why** — deadline, size, binary, excluded.
  A vendored minified asset skipped as vendored is a fine entry. `frontend/ (14 files) not
  read — ran out of turns` is a fine entry.
- Which directory groups are closed and which are open.

A visible gap is recoverable: the next agent, or the next stage, picks it up. A silent gap is
permanent, and in the output it is indistinguishable from clean coverage.

## The inventory decides when you are done

Not intuition, not "I have enough for a good report", not the point at which findings stop
arriving. Exploration ends when the set difference between the inventory and the files you have
read to the end is empty, or when every remaining element of it is listed in your coverage
report with a reason. Those are the only two endings.
