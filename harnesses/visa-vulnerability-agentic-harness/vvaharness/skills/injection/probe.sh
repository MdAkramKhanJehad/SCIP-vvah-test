#!/bin/sh
# Injection candidate sweep: one labelled section per injection class, plus a defence census.

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

ROOT="${1:-.}"
CAP=20
XD="--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=venv --exclude-dir=__pycache__ --exclude-dir=dist --exclude-dir=build --exclude-dir=.vvaharness --exclude-dir=vendor"

hits() {
	label=$1
	pat=$2
	shift 2
	printf '\n== %s ==\n' "$label"
	out=$(grep -rEn --binary-files=without-match $XD "$pat" "$@" "$ROOT" 2>/dev/null || true)
	if [ -z "$out" ]; then
		echo "(none)"
	else
		printf '%s match(es); showing up to %s\n' "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" "$CAP"
		printf '%s\n' "$out" | head -n "$CAP"
	fi
}

count() {
	printf '%-42s ' "$1"
	shift
	grep -rEl --binary-files=without-match $XD "$1" "$ROOT" 2>/dev/null | wc -l | tr -d ' '
}

echo "INJECTION CANDIDATE SWEEP under: $ROOT"
echo "Every line below is a CANDIDATE. Apply the hard gate before reporting anything."

hits "SQL text with interpolation or concatenation" \
	'(SELECT|INSERT[[:space:]]+INTO|UPDATE|DELETE[[:space:]]+FROM)[^;]*(\+|%s|%d|\.format\(|\{[A-Za-z_])'
hits "execute/query/raw on a non-literal argument" \
	'\.(execute|executemany|executeQuery|executeUpdate|query|raw|queryRaw)[[:space:]]*\(([A-Za-z_]|f["'"'"'])'
hits "ORM raw-query escape hatches" \
	'\.(extra|raw)\(|[^A-Za-z_]text\(|createNativeQuery|\$queryRaw|\$executeRaw|where\([^)]*#\{'
hits "NoSQL operator / server-side JS" \
	'\$where|\$function|\$accumulator|mapReduce\(|\.aggregate\('
hits "OS command execution" \
	'os\.system|os\.popen|shell[[:space:]]*=[[:space:]]*True|subprocess\.(run|call|Popen|check_output)|Runtime\.getRuntime\(\)\.exec|ProcessBuilder|child_process|execSync|spawnSync|Kernel\.(system|exec)|%x\{|qx[({/#|]|(open|system|exec)[[:space:]]*\([[:space:]]*['"'"'"]?[^)]*\|'
# Backticks mean command execution only in Ruby / Perl / shell; in JS/TS they are template
# literals and in Markdown inline code, so this alternative is confined to those file types.
hits "backtick command execution with interpolation (Ruby / Perl / shell)" \
	'`[^`]*(\$\{?[A-Za-z_@]|#\{)[^`]*`' \
	--include='*.rb' --include='*.pl' --include='*.pm' --include='*.sh' --include='*.bash' --include='Rakefile'
hits "dynamic code evaluation" \
	'[^A-Za-z_](eval|exec)\(|new Function\(|Function\([^)]*\)[[:space:]]*\(|set(Timeout|Interval)\([[:space:]]*["'"'"']|__import__\(|pickle\.loads|yaml\.load\('
hits "LDAP / XPath queries" \
	'DirContext|InitialLdapContext|ldap3|python-ldap|\.search_s?\(|XPathExpression|selectSingleNode|selectNodes|\.xpath\('
hits "XML parser factories (check hardening flags yourself)" \
	'DocumentBuilderFactory|SAXParserFactory|XMLInputFactory|TransformerFactory|SAXReader|XmlPullParser|etree\.(parse|fromstring|XMLParser)|xml\.dom\.minidom|expatreader|XmlDocument'
hits "outbound HTTP clients (SSRF sinks)" \
	'requests\.(get|post|put|delete|head|request)|urlopen|urllib[0-9]?\.|http\.client|HttpURLConnection|OkHttpClient|HttpClient|WebClient|RestTemplate|Net::HTTP|axios\.|[^A-Za-z_]fetch\('
hits "filesystem open / archive extraction" \
	'[^A-Za-z_.]open\([^)]*(\+|%s|\.format\(|f["'"'"'])|os\.path\.join\(|fs\.(read|write|create)File|new File\(|Path(s)?\.(of|get)\(|extractall|\.extract\(|TarFile|ZipFile|send_file|sendFile|static_file'
hits "template autoescape bypass (server-emitted XSS)" \
	'\|[[:space:]]*safe|autoescape[[:space:]]*=[[:space:]]*False|mark_safe|html_safe|[^A-Za-z_]raw\(|\{\{\{|dangerouslySetInnerHTML|innerHTML[[:space:]]*='
hits "SSTI — input rendered AS a template" \
	'render_template_string|Template[[:space:]]*\(|new SimpleTemplateEngine|ERB\.new|Velocity\.evaluate|Jinja2?\(|from_string\('
hits "redirect writers (open redirect)" \
	'redirect\([^)]*(request|req|params|query|next|url|returnUrl)|res\.redirect\(|sendRedirect\(|Response\.Redirect|redirect_to[[:space:]]'
hits "response header / cookie writes (CRLF)" \
	'headers?\[[^]]*\][[:space:]]*=|setHeader\(|add_header\(|set_cookie\(|addCookie\(|Set-Cookie'
hits "regex compiled from a variable" \
	'(re\.compile|Pattern\.compile|new RegExp|Regexp\.new|regexp\.MustCompile)\([[:space:]]*[A-Za-z_][A-Za-z_0-9.]*[[:space:]]*[,)]'
hits "nested-quantifier regex literals (ReDoS)" \
	'\([^)]*[*+][^)]*\)[*+]|\([^|)]+\|[^|)]+\)[*+][^?]'

printf '\n== DEFENCE CENSUS (files containing each marker) ==\n'
count "parameter placeholders (?, :name, \$1)" '(execute|query)\([^)]*(\?|:[a-z_]+|\$[0-9])'
count "shlex.quote / escapeshellarg / Shellwords" 'shlex\.quote|escapeshellarg|Shellwords|quote_plus'
count "allow-list vocabulary" '(allow|white)_?list|ALLOW(ED)?_(HOSTS|SCHEMES|ORIGINS)|in[[:space:]]+\{?["'"'"']'
count "context escapers" 'escape\(|html\.escape|escapeHtml|quote_ident|urlencode|encodeURIComponent'
count "XXE hardening flags" 'disallow-doctype-decl|FEATURE_SECURE_PROCESSING|external-general-entities|resolve_entities|no_network'
count "canonical-path checks" 'realpath|resolve\(\)|abspath|normpath|Canonical'

printf '\n(end of sweep)\n'
exit 0
