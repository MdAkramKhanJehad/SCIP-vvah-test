#!/bin/sh
# SSRF probe: greps outbound-fetch sinks, url-parameter helper contracts, request sources and
# redirect/allow-list posture across seven ecosystems, grouped so an empty section is a finding.

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
ROOT=${1:-.}
CAP=${SSRF_PROBE_CAP:-12}
WIDTH=140
EX="--exclude-dir=.git --exclude-dir=node_modules --exclude-dir=.venv --exclude-dir=venv
--exclude-dir=.tox --exclude-dir=dist --exclude-dir=build --exclude-dir=__pycache__
--exclude-dir=site-packages --exclude-dir=.mypy_cache --exclude-dir=target
--exclude-dir=.next --exclude-dir=coverage
--exclude-dir=.vvaharness --exclude-dir=security-scan --exclude=SKILL.md --exclude=probe.sh"

# scan LABEL "INCLUDE_GLOBS" "ERE" — prints capped path:line hits, or (none).
scan() {
	_label=$1
	_globs=$2
	_pat=$3
	_inc=
	for _g in $_globs; do _inc="$_inc --include=$_g"; done
	echo "== $_label =="
	_out=$(grep -rEn --binary-files=without-match $_inc $EX -- "$_pat" "$ROOT" 2>/dev/null || true)
	if [ -z "$_out" ]; then
		echo "(none)"
	else
		FOUND=1
		_n=$(printf '%s\n' "$_out" | wc -l | tr -d ' ')
		printf '%s\n' "$_out" | head -n "$CAP" | cut -c1-$WIDTH
		[ "$_n" -gt "$CAP" ] && echo "... $_n hits total, showing $CAP - grep this pattern yourself for the rest"
	fi
	echo ""
}

# count LABEL "INCLUDE_GLOBS" "ERE" — prints only the match count and a 3-line sample.
count() {
	_label=$1
	_globs=$2
	_pat=$3
	_inc=
	for _g in $_globs; do _inc="$_inc --include=$_g"; done
	echo "== $_label =="
	_out=$(grep -rEn --binary-files=without-match $_inc $EX -- "$_pat" "$ROOT" 2>/dev/null || true)
	if [ -z "$_out" ]; then
		echo "(none)"
	else
		printf '%s hits; sample:\n' "$(printf '%s\n' "$_out" | wc -l | tr -d ' ')"
		printf '%s\n' "$_out" | head -n 3 | cut -c1-$WIDTH
	fi
	echo ""
}

PY='*.py *.pyi'
JS='*.js *.jsx *.ts *.tsx *.mjs *.cjs *.vue *.svelte'
JV='*.java *.kt *.kts *.scala *.groovy'
RB='*.rb *.rake *.erb Gemfile Rakefile'
PH='*.php *.phtml *.inc'
GO='*.go'
NET='*.cs *.vb *.fs *.fsx'

echo "### SSRF PROBE root=$ROOT"
echo ""

scan "PYTHON FETCH SINKS" "$PY" \
	'requests\.(get|post|put|patch|delete|head|request)|Session\(\)?\.(get|post|request)|httpx\.(get|post|request|stream|Client|AsyncClient)|urllib\.request|urlopen|urlretrieve|http\.client\.HTTP|aiohttp\.(ClientSession|request)|pycurl|socket\.(connect|create_connection)|smtplib\.|ftplib\.'

scan "JS/TS FETCH SINKS" "$JS" \
	'\bfetch\(|axios[.(]|node-fetch|undici|require\(.got.\)|from .got.|\bsuperagent|\bhttps?\.(get|request)\(|\.goto\(|new URL\([^)]*(url|uri|src|input|req)'

scan "JAVA/KOTLIN FETCH SINKS" "$JV" \
	'OkHttpClient|Request\.Builder|HttpRequest\.newBuilder|RestTemplate|WebClient\.|HttpClient\.(send|newHttpClient)|new URL\(|openConnection\(|HttpGet|HttpPost|URI\.create|Jsoup\.connect'

scan "RUBY FETCH SINKS" "$RB" \
	'Net::HTTP|URI\.(open|parse)|open-uri|Faraday|HTTParty|RestClient|Excon|Typhoeus'

scan "PHP FETCH SINKS" "$PH" \
	'curl_(init|setopt|exec)|CURLOPT_URL|file_get_contents\s*\(|fopen\s*\(|GuzzleHttp|Guzzle\\|Http::(get|post)|readfile\s*\('

scan "GO FETCH SINKS" "$GO" \
	'http\.(Get|Post|Head|PostForm|NewRequest|NewRequestWithContext)|\.Client\{|[Cc]lient\.Do\(|resty\.|net\.Dial'

scan ".NET FETCH SINKS" "$NET" \
	'HttpClient|WebRequest\.Create|WebClient|HttpWebRequest|GetStringAsync|(Get|Post|Send)Async\(|DownloadString'

scan "INDIRECT FETCH MECHANISMS (render/XXE/image/db)" "" \
	'wkhtmltopdf|WeasyPrint|puppeteer|playwright|pdfkit|imgkit|ImageMagick|wand\.image|pyvips|libvips|rsvg|cairosvg|postgres_fdw|dblink|resolve_entities|XMLResolver|DocumentBuilderFactory|SAXParser|etree\.(parse|fromstring)|libxml|xmlrpc|SimpleXML|LOAD DATA'

scan "URL-PARAMETER CONTRACTS (opaque fetch helpers - sink even with an empty body)" "" \
	'(def|function|func|fun|sub|public|private|protected|static)[^();]*\(([^)]*[^A-Za-z_])?(url|uri|src|source_url|endpoint|callback|callback_url|webhook|webhook_url|href|link|target_url|remote|image_url|feed_url)([^A-Za-z_][^)]*)?\)'

scan "FETCH-NAMED HELPERS (name is the contract)" "" \
	'(def|function|func|fun|public|private|static)[^();]*\b\w*(download|fetch|get_image|get_base64|load_url|loadUrl|import_|render_|screenshot|thumbnail|thumb|preview|unfurl|oembed|proxy_|passthrough|health_?check|test_connection|avatar|favicon|scrape|crawl|mirror|webhook)\w*\s*\('

echo "== CALL SITES OF FETCH-NAMED HELPERS (anchor the finding here, not at the def) =="
_calls=$(grep -rEn --binary-files=without-match $EX -- \
	'\b\w*(download|fetch|get_image|get_base64|load_url|loadUrl|import_url|import_from|render_url|render_pdf|screenshot|thumbnail|thumb|preview|unfurl|oembed|proxy_|passthrough|scrape|crawl|mirror|send_webhook|call_webhook)\w*\s*\(' \
	"$ROOT" 2>/dev/null | grep -vE '\b(def|function|func|fun|sub)\b' || true)
if [ -z "$_calls" ]; then
	echo "(none)"
else
	printf '%s\n' "$_calls" | head -n "$CAP" | cut -c1-$WIDTH
fi
echo ""

scan "REQUEST SOURCES ON URL-SHAPED NAMES" "" \
	'(request\.(args|form|json|values|data|GET|POST|query_params|get_json|headers)|req\.(query|body|params)|\$_(GET|POST|REQUEST)|params\[|form\.\w+\.data|@RequestParam|@RequestBody|@PathVariable|ctx\.(query|request)|c\.Query|r\.(URL|FormValue))[^;]*(url|uri|src|endpoint|callback|webhook|host|link|href|target|image|avatar|feed|address)'

SINKS=$FOUND
CAP=8
scan "REDIRECT / RESOLUTION / ALLOW-LIST POSTURE (empty = gate condition (c) unmet by default)" "" \
	'allow_redirects|follow_redirects|followRedirects|CURLOPT_FOLLOWLOCATION|redirect:\s*.(follow|manual|error)|max_redirects|getaddrinfo|gethostbyname|InetAddress\.getByName|ip_address\(|ipaddress\.|is_private|is_loopback|is_global|urlparse|urlsplit|\.hostname|allow_?list|allowed_?hosts|ALLOWED_HOSTS|whitelist|blocklist|deny_?list|blacklist|proxies\s*=|advocate|validators\.url|URLField|URLValidator'

count "INTERNAL-TARGET AND SCHEME STRINGS PRESENT IN TREE" "" \
	'169\.254\.169\.254|metadata\.google\.internal|100\.100\.200\.200|127\.0\.0\.1|localhost|0\.0\.0\.0|::1|svc\.cluster\.local|\.internal\b|192\.168\.|10\.[0-9]+\.[0-9]+\.[0-9]+|172\.(1[6-9]|2[0-9]|3[01])\.|file://|gopher://|dict://|ldap://|jar:|netdoc:'

echo "== DECLARED HTTP-CLIENT DEPENDENCIES (absence NEVER refutes a fetch sink) =="
_dep=$(grep -rEn --binary-files=without-match $EX \
	--include=requirements*.txt --include=pyproject.toml --include=setup.py --include=Pipfile \
	--include=package.json --include=pom.xml --include=build.gradle* --include=go.mod \
	--include=Gemfile --include=composer.json --include=*.csproj \
	-- 'requests|httpx|aiohttp|urllib3|pycurl|axios|node-fetch|got|undici|superagent|okhttp|httpclient|resttemplate|webflux|faraday|httparty|rest-client|guzzle|curl' \
	"$ROOT" 2>/dev/null || true)
if [ -z "$_dep" ]; then
	echo "(none) - no HTTP client declared; a url-parameter helper is STILL a sink"
else
	printf '%s\n' "$_dep" | head -n 12
fi
echo ""

# Reference tables, printed only when this tree actually has a sink or a url-contract helper.
if [ -n "$SINKS" ]; then
	cat <<'REF'
== REFERENCE: bypasses to name against any host check or deny-list above ==
decimal 2130706433 | octal 0177.0.0.1 | hex 0x7f.1 | short 127.1 | IPv4-mapped [::ffff:127.0.0.1] | [::]
credentials prefix http://allowed.com@169.254.169.254/ | trailing dot metadata.google.internal.
mixed-case scheme HTTP:// FiLe:// | attacker DNS resolving private 127.0.0.1.nip.io
percent-encoded or IDN host | fragment trick http://evil/#@169.254.169.254/

== REFERENCE: redirect following (the allow-list must re-run on EVERY hop) ==
on by default: requests allow_redirects=True | urllib urlopen | JS fetch | OkHttp followRedirects
off, commonly switched on: httpx follow_redirects=True | HttpClient.Builder.followRedirects(ALWAYS) | PHP CURLOPT_FOLLOWLOCATION
an allowed host that 302s to 169.254.169.254 wins unless every hop is re-checked

== REFERENCE: check-then-fetch races (TOCTOU / DNS rebinding) ==
a getaddrinfo / gethostbyname / InetAddress.getByName check followed by a fetch on the original
string resolves twice and can see a different address the second time - same defect when code
inspects urlparse(...).hostname or new URL(s).hostname but hands the raw string to the client

== REFERENCE: internal targets to name, highest impact first ==
metadata (credential theft): 169.254.169.254/latest/meta-data/iam/security-credentials/ (AWS)
  metadata.google.internal + header Metadata-Flavor: Google | 169.254.169.254/metadata/instance + Metadata: true (Azure) | 100.100.200.200 (Alibaba)
private space: localhost 127.x.x.x ::1 0.0.0.0 | 10/8 172.16/12 192.168/16 169.254/16 | *.internal *.local *.svc.cluster.local | unqualified names via search domains
admin ports: 2375 docker | 6379 redis | 9200 elasticsearch | 8500 consul | 10250 kubelet | 5432 3306 db | 15672 rabbit | 9090 prometheus
schemes: file:///etc/passwd | gopher:// crafted TCP to redis/smtp | dict:// | ftp:// | ldap:// | jar: netdoc: in Java
REF
	echo ""
fi

echo "### END SSRF PROBE"
exit 0
