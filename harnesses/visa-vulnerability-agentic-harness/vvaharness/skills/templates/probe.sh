#!/bin/sh
# Template/view-layer sink battery: one read-only pass that prints path:line for every
# unescaped-output marker, dangerous interpolation context, info-disclosure expression and
# CSRF-token-less form across every template dialect in the repo. Usage: sh probe.sh [root]

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

ROOT=${1:-.}

# The --include=*.ext words below are split but must never be glob-expanded by the shell.
set -f

SKIP="--exclude-dir=.git --exclude-dir=.hg --exclude-dir=.svn --exclude-dir=node_modules
--exclude-dir=bower_components --exclude-dir=.venv --exclude-dir=venv --exclude-dir=env
--exclude-dir=site-packages --exclude-dir=__pycache__ --exclude-dir=.tox --exclude-dir=.mypy_cache
--exclude-dir=dist --exclude-dir=build --exclude-dir=target --exclude-dir=out
--exclude-dir=vendor --exclude-dir=.next --exclude-dir=.nuxt --exclude-dir=coverage
--exclude-dir=.vvaharness --exclude=SKILL.md --exclude=probe.sh"

TPL="--include=*.html --include=*.htm --include=*.xhtml --include=*.shtml
--include=*.jinja --include=*.jinja2 --include=*.j2 --include=*.twig --include=*.liquid
--include=*.erb --include=*.haml --include=*.slim --include=*.rhtml
--include=*.ejs --include=*.eta --include=*.hbs --include=*.handlebars --include=*.mustache
--include=*.njk --include=*.nunjucks --include=*.pug --include=*.jade --include=*.marko
--include=*.jsp --include=*.jspx --include=*.jspf --include=*.tag --include=*.ftl --include=*.vm
--include=*.cshtml --include=*.vbhtml --include=*.razor --include=*.aspx --include=*.ascx
--include=*.master --include=*.blade.php --include=*.phtml
--include=*.vue --include=*.svelte --include=*.astro
--include=*.tmpl --include=*.tpl --include=*.gohtml --include=*.mako --include=*.mak"

SRC="--include=*.py --include=*.js --include=*.jsx --include=*.mjs --include=*.cjs
--include=*.ts --include=*.tsx --include=*.rb --include=*.go --include=*.java --include=*.kt
--include=*.cs --include=*.vb --include=*.php --include=*.pl --include=*.ex --include=*.exs
--include=*.config --include=*.xml --include=*.json --include=*.yaml --include=*.yml
--include=*.cfg --include=*.ini --include=*.toml"

sec() {
	echo ""
	echo "== $1 =="
}

# Normalise whitespace and clip long lines: minified template lines must not flood the output.
norm() {
	sed 's/[	 ][	 ]*/ /g' | cut -c1-170
}

# Drop duplicate hits from batteries whose patterns overlap; order by file then line number.
dedup() {
	sort -t: -k1,1 -k2,2n -u
}

# Read matches on stdin, print at most $1 of them, print "(none)" when there were none.
emit() {
	cap=$1
	data=$(head -n 3000)
	if [ -z "$data" ]; then
		echo "(none)"
		return 0
	fi
	total=$(printf '%s\n' "$data" | wc -l | tr -d ' ')
	printf '%s\n' "$data" | head -n "$cap"
	if [ "$total" -gt "$cap" ]; then
		echo "... $total matches, showing first $cap"
	fi
	return 0
}

# Walk the tree for template files once; three sections below reuse the list.
TPL_FILES=$(grep -rlE '^' $SKIP $TPL -- "$ROOT" 2>/dev/null | head -n 5000)

tpl_files() {
	[ -n "$TPL_FILES" ] && printf '%s\n' "$TPL_FILES"
	return 0
}

# grep the template tree for an ERE; $2=-i for case-insensitive
tgrep() {
	grep -rEn $2 $SKIP $TPL -e "$1" -- "$ROOT" 2>/dev/null || true
}

# grep the host source tree for an ERE
sgrep() {
	grep -rEn $2 $SKIP $SRC -e "$1" -- "$ROOT" 2>/dev/null || true
}

echo "== TEMPLATE/VIEW PROBE: root=$ROOT =="

sec "TEMPLATE INVENTORY (non-empty files, by extension)"
tpl_files | awk -F/ '{n=split($NF,p,"."); print "."p[n]}' \
	| awk '{c[$1]++; t++} END{for (k in c) printf "%6d  %s\n", c[k], k; if (t) printf "%6d  TOTAL template files\n", t}' \
	| sort -rn | emit 45

sec "LAYOUTS / PARTIALS / FRAGMENTS — READ THESE BEFORE ANY LEAF PAGE"
tpl_files \
	| grep -Ei '(^|/)(_?base|_?layout|_?master|_?application|_?default|_?main|_?shell|_?wrapper|_?head|_?nav|_?footer|_?header)[^/]*$|/(partials?|fragments?|includes?|shared|components|macros)/' \
	| norm | emit 40

sec "AUTOESCAPE OFF / UNSAFE ENGINE CONFIG -- a bare jinja2.Environment() defaults to autoescape OFF, and select_autoescape(enabled_extensions=('html',)) leaves .txt/.jinja unescaped"
{
	tgrep 'autoescape[^>%}]{0,12}(false|off)' -i
	sgrep 'autoescape[[:space:]]*[=:][[:space:]]*(false|0|None)|jinja2?\.Environment\(|Environment\(loader|select_autoescape|nunjucks\.configure|Handlebars\.compile|new[[:space:]]+Twig|escape[[:space:]]*[=:][[:space:]]*false|escapeXml[^>]{0,12}false|escapeHtml[^>]{0,12}false|ValidateRequest[^>]{0,12}false' -i
	tgrep 'escapeXml[^>]{0,12}false|escapeHtml[^>]{0,12}false|ValidateRequest[^>]{0,12}false' -i
} | dedup | norm | emit 45

sec "UNESCAPED OUTPUT MARKERS IN TEMPLATES (safe/raw/triple-stash/utext)"
tgrep '\|[[:space:]]*(safe|raw|n)[[:space:]]*[}%|]|\{\{\{|\{\{&|<%-|<%==|<%=[[:space:]]*raw|\.html_safe|th:utext|\[\(\$\{|\[\[\$\{|@Html\.Raw|Html\.Raw\(|MvcHtmlString|HtmlString|\{@html|v-html|dangerouslySetInnerHTML|\[innerHTML\]|innerHTML[[:space:]]*=|outerHTML[[:space:]]*=|insertAdjacentHTML|document\.write|Handlebars\.SafeString|mark_safe|SafeString|Markup\(|\{!![[:space:]]|\{%[[:space:]]*filter[[:space:]]+safe' \
	| norm | emit 70

sec "UNESCAPED OUTPUT MARKERS IN HOST CODE (mark_safe / Markup / SafeString / Trust bypass)"
sgrep 'mark_safe|SafeString|markupsafe|Markup\(|format_html\(|\.html_safe|Handlebars\.SafeString|bypassSecurityTrust(Html|Url|Script|Style|ResourceUrl)|dangerouslySetInnerHTML|innerHTML[[:space:]]*=|insertAdjacentHTML|document\.write\(|template\.(HTML|JS|URL|HTMLAttr|CSS)\(|Html\.Raw|new[[:space:]]+HtmlString' \
	| norm | emit 60

sec "MACRO KWARGS THAT MARK A COLUMN SAFE -- the {{value|safe}} sink sits in a vendored package template, not in this repo, so grepping |safe here never finds it"
{
	sgrep 'safe_columns|render_table\(|render_field\(|\|safe'
	tgrep 'safe_columns|render_table\(|bootstrap[0-9]?/table'
} | dedup | norm | emit 30

sec "SSTI — TEMPLATE SOURCE BUILT AT RUNTIME (CWE-1336, a separate finding from XSS)"
sgrep 'render_template_string|Template\([^)]*(\+|%|format|f["]|request|input|param)|from_string\(|env\.from_string|Twig.*createTemplate|new[[:space:]]+Template\(|template\.New\([^)]*Parse|eval_template' \
	| norm | emit 30

sec "URL-CONTEXT INTERPOLATION (needs a scheme allow-list; HTML-escaping does nothing here)"
tgrep '(href|src|srcset|action|formaction|poster|cite|data|background|xlink:href|ng-href|:href|:src|th:href|th:src|location(\.href)?|window\.open)[[:space:]]*=[[:space:]]*[^>]{0,60}(\{\{|\{%|<%|\$\{|#\{|\[\[\$|\[\(\$)' \
	| norm | emit 60

sec "EVENT-HANDLER-CONTEXT INTERPOLATION (attribute body is JS; HTML entities decode first)"
tgrep '(on[a-z]{3,20}|th:on[a-z]+|v-on:[a-z]+|@(click|input|change|submit|error|load))[[:space:]]*=[[:space:]]*[^>]{0,60}(\{\{|\{%|<%|\$\{|#\{|\[\[\$|\[\(\$)' \
	| norm | emit 45

sec "SCRIPT-CONTEXT INTERPOLATION (inside <script>; needs tojson / json_script / template.JS)"
SCRIPT_AWK=$(cat <<'AWK'
FNR == 1 { ins = 0 }
{
	l = tolower($0)
	interp = (l ~ /(\{\{|\{%[[:space:]]*(if|for|print)|<%[=-]|\$\{|#\{|\[\[\$|\[\(\$)/)
	opens_here = (l ~ /<script/)
	if (interp && (ins > 0 || opens_here)) {
		enc = (l ~ /tojson|json_script|json\.stringify|escapejs|template\.js|jsonify|jsonencode|\|[[:space:]]*e[[:space:]]*[}|]/) ? "ENCODED?" : "RAW"
		s = $0
		gsub(/[	 ][	 ]*/, " ", s)
		printf "%s:%d: [%s] %s\n", FILENAME, FNR, enc, substr(s, 1, 150)
	}
	ins = ins + gsub(/<script/, "&", l) - gsub(/<\/script/, "&", l)
	if (ins < 0) { ins = 0 }
}
AWK
)
tpl_files | while IFS= read -r f; do
	[ -n "$f" ] && awk "$SCRIPT_AWK" "$f" 2>/dev/null
done | emit 45

sec "UNQUOTED-ATTRIBUTE / CSS-CONTEXT INTERPOLATION (a space starts a new attribute)"
{
	tgrep '[a-zA-Z_:-]+=(\{\{|\{%|<%|\$\{|#\{)'
	tgrep 'style[[:space:]]*=[[:space:]]*[^>]{0,60}(\{\{|<%|\$\{|#\{)'
	tgrep '<style[^>]*>.*(\{\{|<%|\$\{|#\{)'
} | dedup | norm | emit 40

sec "GO TEXT/TEMPLATE (does no escaping at all) AND TYPE-CAST RE-OPENS"
sgrep 'text/template|html/template|template\.(HTML|JS|URL|HTMLAttr|CSS|Srcset)\(' | norm | emit 25

sec "FORMS: CSRF TOKEN FIELD PRESENT INSIDE EACH FORM?"
FORM_AWK=$(cat <<'AWK'
BEGIN { Q = "[" sprintf("%c", 34) sprintf("%c", 39) "]" }
FNR == 1 { if (inform) { flush_form() } ; inform = 0 }
{
	l = tolower($0)
	gsub(Q, "", l)
	rest = l
	while (1) {
		if (!inform) {
			p = index(rest, "<form")
			if (p == 0) { break }
			inform = 1
			startline = FNR
			buf = ""
			rest = substr(rest, p)
		}
		q = index(rest, "</form")
		if (q == 0) { buf = buf " " rest; break }
		buf = buf " " substr(rest, 1, q - 1)
		flush_form()
		inform = 0
		rest = substr(rest, q + 6)
	}
}
END { if (inform) { flush_form() } }
function flush_form() {
	verb = "GET/UNSPECIFIED"
	if (buf ~ /method[ ]*=[ ]*(post|put|delete|patch)/) { verb = "STATE-CHANGING" }
	tok = "NO-TOKEN"
	if (buf ~ /csrf|xsrf|authenticity_token|antiforgerytoken|hidden_tag|_token|requestverificationtoken/) { tok = "token-present" }
	act = "?"
	if (match(buf, /action[ ]*=[ ]*[^ >]+/)) { act = substr(buf, RSTART, RLENGTH) }
	printf "%s:%d: %s %s (%s)\n", FILENAME, startline, verb, tok, act
	forms++
}
AWK
)
FORMS=$(grep -rlE '<[Ff][Oo][Rr][Mm]' $SKIP $TPL -- "$ROOT" 2>/dev/null | while IFS= read -r f; do
	[ -n "$f" ] && awk "$FORM_AWK" "$f" 2>/dev/null
done | sort -t: -k1,1 -k2,2n | head -n 2000)
echo "-- verdict counts over every form found --"
printf '%s\n' "$FORMS" | grep -E 'TOKEN|token' \
	| awk '{c[$2" "$3]++} END{for (k in c) printf "%6d  %s\n", c[k], k}' | sort -rn | emit 10
echo "-- forms with NO token field inside the <form>...</form> span --"
printf '%s\n' "$FORMS" | grep -E 'NO-TOKEN' | emit 60

sec "FORM HELPERS THAT EMIT A TOKEN THEMSELVES (Rails form_with, hidden_tag, form_tag)"
{
	tgrep 'form_with|form_for|form_tag|hidden_tag|csrf_meta_tags|@Html\.BeginForm|\{%[[:space:]]*csrf_token'
	sgrep 'form_with|form_for|form_tag|hidden_tag'
} | dedup | norm | emit 25

sec "CSRF MACHINERY PRESENT REPO-WIDE (zero hits ⇒ EVERY state-changing form is CWE-352)"
{
	grep -rEn $SKIP $TPL $SRC -e 'CSRFProtect|WTF_CSRF|csrf_token|csrfmiddlewaretoken|CsrfViewMiddleware|authenticity_token|protect_from_forgery|AntiForgeryToken|ValidateAntiForgeryToken|csurf|X-CSRF-Token|X-XSRF-TOKEN|csrf-token|_csrf|CsrfTokenRepository|SameSite' -- "$ROOT" 2>/dev/null || true
} | dedup | norm | emit 35
echo "-- form base classes (wtforms.Form has no token; flask_wtf.FlaskForm does) --"
sgrep 'class[[:space:]]+[A-Za-z_]+\((wtforms\.)?(Form|FlaskForm|ModelForm|forms\.Form)\)|from[[:space:]]+flask_wtf|import[[:space:]]+FlaskForm|Flask-WTF|flask-wtf' | norm | emit 25

sec "INFO DISCLOSURE: EXCEPTION / DEBUG OBJECTS RENDERED (CWE-209)"
tgrep '(\{\{|\{%|<%[=-]|\$\{|#\{)[^}%]{0,40}\b(error|errors|exception|exc|traceback|stack|stacktrace|stack_trace|detailed_message|debug_info|sql|query|e\.message|err\.message)\b|@Model\.Exception|Server\.GetLastError|<%=[[:space:]]*e\.' -i \
	| norm | emit 40

sec "INFO DISCLOSURE: CONFIG / SECRETS / HIDDEN FIELDS SHIPPED TO THE CLIENT (CWE-200/540)"
{
	tgrep '(\{\{|\{%|<%[=-]|\$\{|#\{)[^}%]{0,40}\b(config|settings|environ|secret_key|secret|password|passwd|token|api_key|apikey|private_key|access_key|session|is_admin|is_staff|role|permissions|internal)\b' -i
	tgrep '<input[^>]*type[^>]{0,12}(hidden|password)[^>]*value[[:space:]]*='
	tgrep '<!--[^>]{0,120}(\{\{|<%|\$\{|#\{|TODO|FIXME|password|secret|internal)' -i
	tgrep 'data-[a-z-]+[[:space:]]*=[[:space:]]*[^>]{0,40}(user_id|userid|email|is_admin|role|token|secret)' -i
} | dedup | norm | emit 50

sec "DEBUG MODE / STACKTRACE EXPOSURE IN CONFIG (turns any error page into CWE-209)"
sgrep 'debug[[:space:]]*[=:][[:space:]]*(True|true|1)|FLASK_DEBUG|app\.run\([^)]*debug|DEBUG_PROPAGATE|traceback\.(format_exc|print_exc)|customErrors[^>]{0,20}Off|UseDeveloperExceptionPage|consider_all_requests_local|show_exceptions|ASPNETCORE_ENVIRONMENT[^ ]{0,20}Development|config\.consider' \
	| norm | emit 35

sec "SANITIZERS AND ENCODERS PRESENT (refutation candidates — name the one on the write path)"
{
	sgrep 'bleach\.|nh3\.|DOMPurify|sanitize_html|sanitizeHtml|HtmlSanitizer|OWASP|Sanitizers\.|html\.escape|escape\(|cgi\.escape|htmlspecialchars|ERB::Util|CGI\.escapeHTML|\|tojson|json_script|escapejs|ValidationError|validators\.URL|urlparse|allowed_schemes'
	tgrep '\|[[:space:]]*(e|escape|forceescape|tojson|urlencode|striptags)\b|json_script|escapejs|fn:escapeXml|<c:out'
} | dedup | norm | emit 40

sec "RENDER CALL SITES (template name -> route that supplies the kwargs)"
sgrep 'render_template\(|render_template_string\(|render_to_string|render_to_response|res\.render\(|\.render\([^)]*(html|hbs|ejs|pug|jinja|twig|erb)|template\.Execute|ExecuteTemplate|c\.HTML\(|View\([^)]|return[[:space:]]+view\(|@Controller|@RenderPage' \
	| norm | emit 50

sec "CONTENT SECURITY POLICY (lowers severity; does not refute URL/attribute context)"
{
	sgrep 'Content-Security-Policy|unsafe-inline|unsafe-eval|script-src|nonce|Talisman|helmet'
	tgrep 'Content-Security-Policy|http-equiv[^>]{0,20}Content-Security'
} | dedup | norm | emit 25

echo ""
echo "== END OF PROBE (sections printing (none) are themselves findings) =="
exit 0
