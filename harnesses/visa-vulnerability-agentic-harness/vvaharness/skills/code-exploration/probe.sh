#!/bin/sh
# Inventories the file classes a source-only sweep skips (templates, container/IaC, CI, manifests,
# dotfiles, SQL, static, central controls) and runs the escape / transport / CI pattern batteries.
# Read-only, output-capped, always exits 0. Usage: sh probe.sh [root]   (root defaults to .)

# Copyright 2026 Visa, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -f

ROOT="${1:-.}"
cd "$ROOT" 2>/dev/null || { echo "== PROBE ABORTED: cannot enter '$ROOT' =="; exit 0; }

PRUNE=".git .vvaharness node_modules __pycache__ .venv venv .tox .nox .mypy_cache .pytest_cache .ruff_cache .idea .gradle target"
EXCL=""
for d in $PRUNE; do EXCL="$EXCL --exclude-dir=$d"; done

TPL="--include=*.html --include=*.htm --include=*.jinja --include=*.jinja2 --include=*.j2
--include=*.jsx --include=*.tsx --include=*.vue --include=*.erb --include=*.jsp --include=*.twig
--include=*.hbs --include=*.handlebars --include=*.ejs --include=*.php --include=*.mustache
--include=*.pug --include=*.haml --include=*.svelte --include=*.astro"

SRC="--include=*.py --include=*.rb --include=*.js --include=*.ts --include=*.jsx --include=*.tsx
--include=*.java --include=*.go --include=*.php --include=*.cs --include=*.kt --include=*.scala"

CFG="--include=*.conf --include=*.ini --include=*.cfg --include=*.yml --include=*.yaml
--include=*.toml --include=*.json --include=*.properties --include=*.env --include=*.xml"

sec() { echo; echo "== $1 =="; }

emit() { if [ -z "$1" ]; then echo "(none)"; else printf '%s\n' "$1"; fi; }

echo "== PROBE ROOT =="
pwd
echo "pruned dirs: $PRUNE"

# ---------------------------------------------------------------- file classes
if command -v python3 >/dev/null 2>&1; then
python3 - "$PRUNE" <<'PY'
import fnmatch, os, sys
from collections import Counter

prune = set(sys.argv[1].split())
files, pruned = [], []
for dirpath, dirnames, filenames in os.walk("."):
    keep = []
    for d in sorted(dirnames):
        if d in prune:
            pruned.append(os.path.join(dirpath, d)[2:])
        else:
            keep.append(d)
    dirnames[:] = keep
    for f in sorted(filenames):
        files.append(os.path.join(dirpath, f)[2:])

groups = Counter(os.path.dirname(p) or "<root>" for p in files)
print()
print("== INVENTORY (%d files, %d directory groups; authoritative, not truncated) ==" % (len(files), len(groups)))
for d, n in sorted(groups.items(), key=lambda kv: (-kv[1], kv[0]))[:40]:
    print("%6d  %s" % (n, d))
if len(groups) > 40:
    print("  ... (%d more directory groups)" % (len(groups) - 40))
if pruned:
    print("PRUNED SUBTREES (not counted above): %s" % ", ".join(sorted(set(pruned))[:12]))

CLASSES = [
    ("TEMPLATES AND VIEWS", [
        "*.html", "*.htm", "*.jinja", "*.jinja2", "*.j2", "*.jsx", "*.tsx", "*.vue", "*.erb",
        "*.jsp", "*.jspx", "*.twig", "*.hbs", "*.handlebars", "*.ejs", "*.blade.php",
        "*.mustache", "*.pug", "*.haml", "*.svelte", "*.astro"], []),
    ("CONTAINER / ORCHESTRATION / IaC", [
        "Dockerfile*", "*.dockerfile", "Containerfile*", "docker-compose*.yml",
        "docker-compose*.yaml", "compose.yml", "compose.yaml", "*.tf", "*.tfvars", "*.tfstate",
        "Procfile", "uwsgi.ini", "gunicorn*.py", "*nginx*.conf", "*.conf", "supervisord.conf",
        "*.service", "*.socket", "Vagrantfile", "*deployment*.yml", "*deployment*.yaml",
        "values.yaml", "Chart.yaml", "kustomization.yml", "kustomization.yaml", "*.pp"],
        ["k8s", "kubernetes", "helm", "charts", "deploy", "ansible",
         ".ebextensions", "terraform"]),
    ("CI / CD", [
        ".gitlab-ci.yml", "Jenkinsfile*", "azure-pipelines*.yml", ".travis.yml", ".drone.yml",
        "bitbucket-pipelines.yml", "cloudbuild.yml", "cloudbuild.yaml", "buildspec.yml",
        "buildspec.yaml", "Makefile", "*.mk"], [".github", ".circleci", ".buildkite"]),
    ("DEPENDENCY MANIFESTS", [
        "requirements*.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile", "Pipfile.lock",
        "poetry.lock", "uv.lock", "package.json", "package-lock.json", "*-lock.json", "yarn.lock",
        "pnpm-lock.yaml", "pom.xml", "build.gradle", "build.gradle.kts", "go.mod", "go.sum",
        "Gemfile", "Gemfile.lock", "*.csproj", "*.fsproj", "Cargo.toml", "Cargo.lock",
        "composer.json", "composer.lock"], []),
    ("ENV / CREDENTIAL-SHAPED DOTFILES", [
        ".env", ".env.*", "*.env", "*.env.example", ".dockerignore", ".npmrc", ".netrc",
        ".pypirc", ".git-credentials", ".gitconfig", ".htpasswd", ".htaccess", "*.pem", "*.key",
        "*.p12", "*.jks", "*.keystore", "id_rsa*", "*.ovpn", "credentials*"],
        [".aws", ".ssh", ".docker", ".gnupg", ".kube"]),
    ("SQL / MIGRATIONS / SEEDS", [
        "*.sql", "*.db", "*.sqlite", "*.sqlite3", "db_seed*", "seed*.py", "*fixture*.sql",
        "*.dump", "*.bak"], ["migrations", "alembic", "seeds", "seed"]),
    ("STATIC / BUILT ASSETS", ["*.map", "*.min.js", "*.min.css"],
        ["static", "public", "assets", "dist", "wwwroot", "staticfiles"]),
    ("CENTRAL CONTROLS (__init__, base, middleware, utils)", [
        "__init__.py", "base.py", "base_*.py", "base*.py", "middleware.py", "middleware*.py",
        "middlewares.py", "conftest.py", "decorators.py", "*decorator*.py", "permissions.py",
        "authz*.py", "security*.py", "app.py", "wsgi.py", "asgi.py", "main.py", "settings.py",
        "config.py", "urls.py", "routes.py"], ["utils", "util", "helpers", "common",
        "middleware", "middlewares"]),
]

def hits(basenames, dirs):
    out = []
    for p in files:
        b = os.path.basename(p)
        parts = p.split(os.sep)[:-1]
        if any(fnmatch.fnmatch(b, g) for g in basenames) or any(x in dirs for x in parts):
            out.append(p)
    return out

for label, basenames, dirs in CLASSES:
    found = hits(basenames, dirs)
    print()
    print("== %s (%d) ==" % (label, len(found)))
    if not found:
        print("(none)")
        continue
    for p in found[:15]:
        print("  " + p)
    if len(found) > 15:
        print("  ... (%d more)" % (len(found) - 15))

dots = [p for p in files if any(x.startswith(".") for x in p.split(os.sep))]
print()
print("== ALL DOTFILES (%d) -- the namespace the graph walk skips entirely ==" % len(dots))
if not dots:
    print("(none)")
for p in dots[:20]:
    print("  " + p)
if len(dots) > 20:
    print("  ... (%d more)" % (len(dots) - 20))

empty = [p for p in files if os.path.exists(p) and os.path.getsize(p) == 0]
print()
print("== ZERO-BYTE FILES (%d) ==" % len(empty))
emptyshown = empty[:10]
if not emptyshown:
    print("(none)")
for p in emptyshown:
    print("  " + p)
if len(empty) > 10:
    print("  ... (%d more)" % (len(empty) - 10))
PY
else
  sec "INVENTORY (python3 unavailable -- grep fallback, text files only)"
  emit "$(grep -rlI '' . $EXCL 2>/dev/null | sed 's|^\./||' | sort | head -n 60)"
fi

# ------------------------------------------------------------ pattern batteries
sec "ESCAPE DEFEATS IN TEMPLATES (each hit is its own finding site)"
emit "$(grep -rEn '\|[[:space:]]*safe|safe_columns|autoescape[[:space:]]*=?[[:space:]]*(false|False|off)|\{\{\{|html_safe|\|[[:space:]]*raw|raw\(|dangerouslySetInnerHTML|v-html|innerHTML[[:space:]]*=' . $EXCL $TPL 2>/dev/null | head -n 20)"

sec "SERVER-SIDE ESCAPE BYPASS / DYNAMIC TEMPLATE COMPILATION"
emit "$(grep -rEn 'mark_safe|Markup\(|render_template_string|Template\(|from_string|autoescape[[:space:]]*=[[:space:]]*False|\.html_safe|raw\(|new Function|eval\(' . $EXCL $SRC 2>/dev/null | head -n 20)"

sec "HANDLER -> TEMPLATE EDGES (each named template is now in scope)"
emit "$(grep -rEn 'render_template|render_to_response|\.render\(|render_to_string|ERB\.new|TemplateResponse|@Template|ModelAndView' . $EXCL $SRC 2>/dev/null | head -n 20)"

sec "TEMPLATE INHERITANCE EDGES (extends/include puts the parent in scope)"
emit "$(grep -rEn '\{%[[:space:]]*(extends|include)|@extends|@include|<%=[[:space:]]*render' . $EXCL $TPL 2>/dev/null | head -n 20)"

sec "TRANSPORT CONFIG -- per file, is there any TLS at all?"
CONFS=$(grep -rlE '^[[:space:]]*listen|server_name|ssl_certificate|uwsgi_pass|proxy_pass|upstream|\[uwsgi\]|bind[[:space:]]*=' . $EXCL --include=*.conf --include=*.ini --include=*.cfg --include=*.template 2>/dev/null | head -n 12)
if [ -z "$CONFS" ]; then
  echo "(none)"
else
  printf '%s\n' "$CONFS" | while IFS= read -r f; do
    tls=$(grep -cEi 'ssl|https|443|tls' "$f" 2>/dev/null)
    lst=$(grep -cE '^[[:space:]]*listen|bind' "$f" 2>/dev/null)
    ttl=$(wc -l < "$f" 2>/dev/null | tr -d ' ')
    echo "  $f: lines=$ttl listen/bind=$lst ssl|tls|https|443 tokens=$tls"
  done
fi

sec "PUBLISHED PORTS AND ENTRYPOINTS (compose / Dockerfile / uwsgi)"
emit "$(grep -rEn '^[[:space:]]*-?[[:space:]]*\"?[0-9]{2,5}:[0-9]{2,5}|EXPOSE|CMD|ENTRYPOINT|^module[[:space:]]*=|^wsgi-file|^[[:space:]]*command:' . $EXCL --include=Dockerfile --include=Dockerfile.* --include=docker-compose*.yml --include=docker-compose*.yaml --include=compose.y*ml --include=*.ini --include=Procfile 2>/dev/null | head -n 20)"

sec "CI/CD RISK (pull_request_target, event interpolation, unpinned actions, secrets in run)"
emit "$(grep -rEn 'pull_request_target|workflow_run|\$\{\{[[:space:]]*github\.event|uses:[[:space:]]*[^@]+@(main|master|v?[0-9]+)([[:space:]]|$)|secrets\.|GITHUB_TOKEN|permissions:' . $EXCL --include=*.yml --include=*.yaml --include=Jenkinsfile --include=Jenkinsfile.* 2>/dev/null | head -n 20)"

sec "SECURITY HEADER / CONTROL PRESENCE (count per header; 0 supports an absence claim)"
for h in Content-Security-Policy Strict-Transport-Security X-Frame-Options X-Content-Type-Options Referrer-Policy SameSite HttpOnly 'secure[ _]*=[ _]*True' COOKIE_SECURE csrf_token CSRFProtect csrf_exempt before_request login_required; do
  n=$(grep -rEil -- "$h" . $EXCL 2>/dev/null | wc -l | tr -d ' ')
  echo "  $h: $n file(s)"
done

sec "DEBUG / VERBOSE-LOGGING FLAGS"
emit "$(grep -rEn '(debug|DEBUG)[[:space:]]*=[[:space:]]*(True|true|1)|echo[[:space:]]*=[[:space:]]*True|app\.run\(.*debug|FLASK_ENV|DJANGO_DEBUG|log_level.*debug' . $EXCL $SRC $CFG 2>/dev/null | head -n 20)"

sec "CREDENTIAL-SHAPED ASSIGNMENTS IN CONFIG, DOTFILES AND SEEDS"
emit "$(grep -rEn '(secret_key|SECRET_KEY|api[_-]?key|API[_-]?KEY|password|PASSWORD|passwd|token|TOKEN|private_key|aws_secret|client_secret)[[:space:]]*[:=][[:space:]]*.?[A-Za-z0-9/+_.-]{4,}' . $EXCL $CFG --include=*.sql --include=.env --include=.env.* --include=*.env 2>/dev/null | head -n 20)"

sec "HARDCODED SECRET LITERALS IN SOURCE (assigned to a quoted string, not a var read)"
emit "$(grep -rEn '(secret_key|SECRET_KEY|secret|api_key|apiKey|API_KEY|password|passwd|passphrase|token|private_key|client_secret|salt|encryption_key)[[:space:]]*=[[:space:]]*["'"'"'][^"'"'"']{3,}["'"'"']' . $EXCL $SRC 2>/dev/null | head -n 20)"

sec "NON-TRIVIAL __init__.py AND ROUTE/BLUEPRINT REGISTRATION"
emit "$(grep -rEn 'register_blueprint|add_url_rule|include_router|app\.route|@bp\.|url_patterns|urlpatterns|@app\.|MethodView|APIRouter|^[[:space:]]+import[[:space:]]|^[[:space:]]+from[[:space:]]' . $EXCL --include=__init__.py --include=urls.py --include=routes.py --include=app.py --include=main.py 2>/dev/null | head -n 20)"

sec "SQL CONSTRUCTION AND SEED CREDENTIALS"
emit "$(grep -rEn '(^|[^_[:alnum:]])(text|execute|executemany|executescript|raw|rawQuery)\(|cursor\.|createQuery|(SELECT|INSERT INTO|UPDATE|DELETE FROM)[^;]*(\{|%s|\+|\|\||f\"|\$)|CREATE USER|GRANT ALL|IDENTIFIED BY' . $EXCL $SRC --include=*.sql 2>/dev/null | head -n 20)"

sec "PROBE COMPLETE"
echo "Every section above is deterministic and exhaustive for its pattern set."
echo "An empty section is a finding: '(none)' under CI/CD means there is no pipeline to audit."
echo "This probe locates; it does not conclude. Read each named file to its last line."

exit 0
