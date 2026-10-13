#!/bin/sh
# Client-side sink battery: one read-only pass over a repo's browser-delivered code,
# printing path:line hits per CWE class (see skills/client-side/SKILL.md). Usage: sh probe.sh [root]

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

EXC='--exclude-dir=node_modules --exclude-dir=.git --exclude-dir=dist --exclude-dir=build
--exclude-dir=coverage --exclude-dir=.next --exclude-dir=out --exclude-dir=vendor
--exclude-dir=__pycache__ --exclude-dir=.venv --exclude-dir=bower_components
--exclude-dir=__mocks__ --exclude-dir=__tests__ --exclude-dir=cypress --exclude-dir=e2e
--exclude-dir=.storybook --exclude-dir=stories --exclude-dir=test --exclude-dir=tests
--exclude=*.min.js --exclude=*-min.js --exclude=*.bundle.js --exclude=*.map
--exclude=*.test.* --exclude=*.spec.* --exclude=*.stories.* --exclude=*.example*
--exclude-dir=.vvaharness --exclude-dir=security-scan --exclude=SKILL.md --exclude=probe.sh'

JS='--include=*.js --include=*.jsx --include=*.ts --include=*.tsx --include=*.mjs
--include=*.cjs --include=*.vue --include=*.svelte'

TPL='--include=*.html --include=*.htm --include=*.ejs --include=*.hbs --include=*.handlebars
--include=*.pug --include=*.jade --include=*.erb --include=*.twig --include=*.mustache
--include=*.njk --include=*.liquid'

CFG='--include=*.json --include=*.env --include=.env* --include=*.yml --include=*.yaml
--include=Dockerfile* --include=*.conf'

SRV='--include=*.py --include=*.rb --include=*.php --include=*.java --include=*.go
--include=*.cs --include=*.js --include=*.ts --include=*.kt --include=*.scala'

CLIENT="$JS $TPL"

# scan <label> <include-flags> <extended-regex> [cap]
scan() {
	_label=$1
	_inc=$2
	_re=$3
	_cap=${4:-10}
	printf '\n== %s ==\n' "$_label"
	_hits=$(grep -rEnIs $EXC $_inc -e "$_re" "$ROOT" 2>/dev/null || true)
	if [ -z "$_hits" ]; then
		echo "(none)"
		return 0
	fi
	_n=$(printf '%s\n' "$_hits" | wc -l | tr -d ' ')
	printf '%s\n' "$_hits" | head -n "$_cap" | sed 's/\(.\{200\}\).*/\1 .../'
	if [ "$_n" -gt "$_cap" ]; then
		printf '... %s hits total, %s shown\n' "$_n" "$_cap"
	fi
	return 0
}

echo "== CLIENT-SIDE PROBE =="
echo "root: $ROOT"
echo "each section is capped; '(none)' means the pattern class is absent, not that the probe failed"

printf '\n== INVENTORY / FILES OF INTEREST ==\n'
python3 - "$ROOT" <<'PY' 2>/dev/null || echo "(inventory unavailable)"
import collections, os, sys

root = sys.argv[1]
exts = {'.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.vue', '.svelte', '.html', '.htm',
        '.ejs', '.hbs', '.handlebars', '.pug', '.jade', '.erb', '.twig', '.mustache'}
skip = {'node_modules', '.git', 'dist', 'build', 'coverage', '.next', 'out', 'vendor',
        '__pycache__', '.venv', 'bower_components'}
interesting = ('package.json', 'package-lock.json', 'yarn.lock', 'pnpm-lock.yaml',
               '.dockerignore', '.npmrc', 'webpack.config.js', 'vite.config.js',
               'vite.config.ts', 'next.config.js', 'next.config.mjs', 'nuxt.config.js',
               'angular.json', 'setupProxy.js', 'config.js', 'constants.js',
               'constants.ts', 'environment.prod.ts', 'service-worker.js')
counts = collections.Counter()
dirs = collections.Counter()
files = []
for dirpath, dirnames, filenames in os.walk(root):
    dirnames[:] = [d for d in dirnames if d not in skip]
    for name in filenames:
        rel = os.path.relpath(os.path.join(dirpath, name), root)
        ext = os.path.splitext(name)[1].lower()
        if ext in exts and not name.endswith(('.min.js', '-min.js', '.bundle.js')):
            counts[ext] += 1
            dirs[os.sep.join(rel.split(os.sep)[:2])] += 1
        if (name in interesting or name.startswith('.env') or name.startswith('Dockerfile')
                or name.endswith('.map')):
            files.append(rel)
if counts:
    print('client files: ' + ', '.join('%s=%d' % kv for kv in counts.most_common()))
    for d, n in dirs.most_common(10):
        print('  %6d  %s' % (n, d))
else:
    print('client files: (none)')
if files:
    print('files of interest:')
    for f in sorted(files)[:30]:
        print('  ' + f)
    if len(files) > 30:
        print('  ... %d total' % len(files))
else:
    print('files of interest: (none)')
for lock in ('package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'):
    if os.path.exists(os.path.join(root, lock)):
        print('lockfile: ' + lock)
        break
else:
    if os.path.exists(os.path.join(root, 'package.json')):
        print('lockfile: NONE beside package.json -- ^ ranges resolve at build time')
PY

scan 'SECRET LITERALS (CWE-798)' "$CLIENT $CFG" \
	'(sk_live_|sk_test_|rk_live_|AKIA[0-9A-Z]{6}|ASIA[0-9A-Z]{6}|AIza[0-9A-Za-z_-]{10}|ghp_[0-9A-Za-z]{10}|gho_[0-9A-Za-z]{10}|glpat-|xox[baprs]-|SG\.[0-9A-Za-z_-]{10}|-----BEGIN [A-Z ]*PRIVATE KEY|mongodb(\+srv)?://[^ "'"'"']*:|postgres(ql)?://[^ "'"'"']*:)' 15

scan 'CREDENTIAL-SHAPED ASSIGNMENTS (CWE-798, CWE-540)' "$CLIENT $CFG" \
	'(api_?[kK]ey|apiSecret|client_?[sS]ecret|secret_?[kK]ey|access_?[kK]ey|private_?[kK]ey|password|passwd|pepper|salt|firebaseConfig|connectionString)[[:space:]]*[:=][[:space:]]*("[^"]{6,}"|'"'"'[^'"'"']{6,}'"'"')' 15

scan 'BUILD-INLINED ENV -- published by definition (CWE-540)' "$CLIENT $CFG" \
	'(REACT_APP_|NEXT_PUBLIC_|VITE_|VUE_APP_|GATSBY_|NUXT_PUBLIC_|EXPO_PUBLIC_|PUBLIC_|DefinePlugin|process\.env\.[A-Z_]+)' 15

scan 'SHIPPED ARTIFACTS / DEV SERVER (CWE-540, CWE-489)' "$CLIENT $CFG" \
	'(sourceMappingURL|GENERATE_SOURCEMAP|productionSourceMap|devtool[[:space:]]*:|CMD[[:space:]]*\[?.*(npm[[:space:]]+(run[[:space:]]+)?(start|dev)|react-scripts[[:space:]]+start|vite|next[[:space:]]+dev|ng[[:space:]]+serve)|^COPY \. |FROM[[:space:]]+node:(8|10|12|14|16)|debug[[:space:]]*[:=][[:space:]]*true)' 15

scan 'HTML SINKS (CWE-79)' "$CLIENT" \
	'(\.innerHTML|\.outerHTML|insertAdjacentHTML|document\.write(ln)?\(|createContextualFragment|\.html\(|\.(append|prepend|after|before|replaceWith)\()' 15

scan 'FRAMEWORK RAW-HTML ESCAPES (CWE-79)' "$CLIENT" \
	'(dangerouslySetInnerHTML|v-html|\[innerHTML\]|bypassSecurityTrust|\{@html|rehype-?[rR]aw|ReactMarkdown|domPropsInnerHTML|Handlebars\.SafeString|\|[[:space:]]*safe|\{\{\{)' 15

scan 'CODE EXECUTION SINKS (CWE-95)' "$CLIENT" \
	'(\beval\(|new Function\(|[^a-zA-Z]Function\(["'"'"']|setTimeout\([[:space:]]*["'"'"'`]|setInterval\([[:space:]]*["'"'"'`]|new Worker\(|importScripts\(|_\.template\(|Vue\.compile\(|vm\.runIn|execScript)' 12

scan 'NAVIGATION / URL SINKS (CWE-79, CWE-601)' "$CLIENT" \
	'(location[[:space:]]*=[^=]|location\.(href|assign|replace)|window\.open\(|\.href[[:space:]]*=[^=]|\.action[[:space:]]*=[^=]|\.src[[:space:]]*=[^=]|srcdoc|setAttribute\([[:space:]]*["'"'"'](href|src|action|formaction|on)|javascript:|data:text/html)' 15

scan 'TAINT SOURCES (CWE-20 inputs, not findings alone)' "$CLIENT" \
	'(location\.(hash|search|pathname|href)|document\.(URL|documentURI|baseURI|referrer|cookie)|window\.name|history\.state|URLSearchParams|useSearchParams|router\.(query|asPath)|useParams\(|\bevent\.data\b|\.onmessage|WebSocket\()' 15

scan 'PROTOTYPE POLLUTION (CWE-1321)' "$CLIENT" \
	'(\$\.extend\([[:space:]]*true|deepmerge|lodash\.merge|_\.merge\(|_\.set\(|_\.setWith|Object\.assign\([[:space:]]*\{\}[[:space:]]*,[[:space:]]*[a-z]|__proto__|\bprototype\[|constructor\[)' 10

scan 'POSTMESSAGE / MESSAGE LISTENERS (CWE-346, CWE-201)' "$CLIENT" \
	'(addEventListener\([[:space:]]*["'"'"']message|\.onmessage[[:space:]]*=|\.postMessage\()' 12

scan 'ORIGIN CHECKS PRESENT -- refutation evidence (CWE-940)' "$CLIENT" \
	'(\.origin[[:space:]]*(===|==|!==|!=)|\.origin\.(indexOf|startsWith|endsWith|match|includes)|ALLOWED_ORIGIN|allowedOrigins|checkOrigin|event\.source)' 10

scan 'FRAME / WINDOW ISOLATION (CWE-1022)' "$CLIENT" \
	'(<iframe|target=["'"'"']_blank|rel=["'"'"'][^"'"'"']*noopener|sandbox=|allow-scripts|window\.opener)' 10

scan 'TOKEN / CREDENTIAL STORAGE (CWE-522, CWE-1004, CWE-1275)' "$CLIENT" \
	'((localStorage|sessionStorage)\.(setItem|getItem)|(localStorage|sessionStorage)\[|document\.cookie[[:space:]]*=|Cookies\.set\(|js-cookie|indexedDB|\.setItem\([[:space:]]*["'"'"'](token|jwt|access_?token|refresh_?token|api_?key|password|user))' 15

scan 'CLIENT-SIDE JWT DECODE (CWE-807)' "$CLIENT" \
	'(atob\(|jwt_?[dD]ecode|jwtDecode|decodeJwt|jose\.decode|split\(["'"'"']\.["'"'"']\)|Buffer\.from\([^,]*,[[:space:]]*["'"'"']base64)' 12

scan 'SECRETS IN CLIENT LOGS (CWE-532)' "$CLIENT" \
	'console\.(log|info|debug|warn|error|table)\([^)]*(token|jwt|password|passwd|secret|api_?key|apiKey|ssn|cvv|card_?number|authorization)' 10

scan 'CLIENT-ONLY AUTHZ / RENDER GATES (CWE-602)' "$CLIENT" \
	'(is_?[aA]dmin|isSuperuser|isStaff|isOwner|(user|auth|currentUser|me|profile|account)\.role|\.role[[:space:]]*(===|==|!==|!=)[[:space:]]*["'"'"'](admin|superuser|root|owner|manager|staff|editor)|hasPermission|hasRole|canActivate|AuthGuard|RequireAuth|isAuthenticated|\.permissions|v-if=["'"'"'][^"'"'"']*(role|admin|permission)|\{[[:space:]]*(user|auth|currentUser)[.a-zA-Z_]*[[:space:]]*&&)' 15

scan 'CLIENT-ONLY WRITE GATES / FORM VALIDATION (CWE-602)' "$CLIENT" \
	'(disabled[[:space:]]*=|readOnly|readonly|type=["'"'"']hidden["'"'"']|maxLength|minLength|pattern=|[[:space:]]required[[:space:]>/]|step=["'"'"']|yup\.|zod|z\.object|Joi\.|useForm\()' 12

scan 'CLIENT-SUPPLIED IDENTITY / AMOUNT -- client send (CWE-639)' "$CLIENT" \
	'(user_?[iI]d|account_?[iI]d|tenant_?[iI]d|customer_?[iI]d|owner_?[iI]d|org_?[iI]d|is_?admin|[^a-zA-Z](amount|price|balance|quantity|discount|total)[[:space:]]*[:=][^=]|(role|is_?admin)[[:space:]]*[:=][[:space:]]*["'"'"']?(admin|superuser|owner|manager|staff|true))' 15

scan 'SERVER READS THAT PARAMETER -- the actual defect (CWE-639)' "$SRV" \
	'((get|\[)[[:space:]]*\(?["'"'"'](user_?id|account_?id|tenant_?id|customer_?id|owner_?id|role|is_?admin|amount|price|balance)["'"'"']|(body|query|params|payload)\.(userId|accountId|tenantId|role|isAdmin|amount|price))' 15

scan 'REQUEST / TRANSPORT CONFIG (CWE-942, CWE-319)' "$CLIENT $CFG" \
	'(mode:[[:space:]]*["'"'"']no-cors|credentials:[[:space:]]*["'"'"']include|withCredentials|Access-Control-Allow-Origin|Allow-Credentials|rejectUnauthorized|NODE_TLS_REJECT_UNAUTHORIZED|window\.location\.(hostname|protocol|host)|"proxy"[[:space:]]*:|setupProxy|http://[a-zA-Z0-9.-]+)' 15

scan 'OPEN REDIRECT (CWE-601)' "$CLIENT" \
	'((location\.href|location\.replace|location\.assign|navigate\(|router\.(push|replace)\(|window\.open\()[^;]*(next|returnUrl|return_to|redirect|continue|callback|from|target|url)|http-equiv=["'"'"']refresh)' 12

scan 'DEPENDENCY PINS with versions (CWE-1104, CWE-1395)' '--include=package.json --include=bower.json' \
	'"[@a-zA-Z0-9._/-]+"[[:space:]]*:[[:space:]]*"[~^>=<* ]*[0-9x]' 40

scan 'EXTERNAL SCRIPTS / SRI (CWE-353)' "$TPL $JS" \
	'(<script[^>]*src=["'"'"'](https?:)?//|<link[^>]*href=["'"'"']https?://|integrity=|crossorigin=)' 12

scan 'PUBLIC-BY-DESIGN KEYS -- refutation evidence' "$CLIENT $CFG" \
	'(pk_live_|pk_test_|firebaseConfig|authDomain|messagingSenderId|ingest\.sentry\.io|sentry.{0,10}[dD][sS][nN]|maps\.googleapis\.com|recaptcha|VITE_PUBLIC|NEXT_PUBLIC_(SITE|URL|BASE))' 10

scan 'SANITIZERS / SAFE SINKS PRESENT -- refutation evidence' "$CLIENT" \
	'(DOMPurify|sanitize-?[hH]tml|sanitizeHtml|\bxss\(|escapeHtml|escape\(|textContent|innerText|encodeURIComponent|DomSanitizer|helmet|CSP|Content-Security-Policy)' 15

printf '\n== END OF PROBE ==\n'
exit 0
