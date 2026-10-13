#!/bin/sh
# Sensitive-data exposure sweep: greps the channels where PII, secrets and internals leak — responses, logs, templates, storage, headers, debug routes.

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
Q="['\"]"
SENS="pass(wd|word)?|secret|token|api_?key|apikey|private_key|credential|ssn|social_security|birth|card_?(no|num|number)|cvv|iban|account_?num|salary|medical|diagnos|flag"

hits() {
	label=$1
	pat=$2
	shift 2
	printf '\n== %s ==\n' "$label"
	out=$(grep -rEni --binary-files=without-match $XD "$pat" "$@" "$ROOT" 2>/dev/null || true)
	if [ -z "$out" ]; then
		echo "(none)"
	else
		printf '%s match(es); showing up to %s\n' "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" "$CAP"
		printf '%s\n' "$out" | head -n "$CAP"
	fi
}

TPL="--include=*.html --include=*.htm --include=*.jinja --include=*.jinja2 --include=*.j2 --include=*.tpl --include=*.erb --include=*.hbs --include=*.twig --include=*.ejs --include=*.vue"
CFG="--include=*settings*.py --include=*config*.py --include=*conf*.py --include=*constants*.py --include=*.properties --include=*settings*.rb --include=*config*.js --include=*config*.ts"

echo "SENSITIVE-DATA EXPOSURE SWEEP under: $ROOT"
echo "Candidates only. Each needs sensitive content AND an attacker-reachable channel."

printf '\n--- ERROR AND DEBUG EXPOSURE ---\n'
hits "debug mode on" 'DEBUG[[:space:]]*=[[:space:]]*True|debug[[:space:]]*=[[:space:]]*True|app\.debug|FLASK_DEBUG|ASPNETCORE_ENVIRONMENT[[:space:]]*[:=][[:space:]]*.?Development|display_errors[[:space:]]*=[[:space:]]*On|NODE_ENV[[:space:]]*[:=][[:space:]]*.?development'
hits "exception text returned to the caller" 'return[^;]*str\(e\)|jsonify\([^)]*(str\(e\)|e\.message|exc)|error[^;]*:[[:space:]]*(str\(|f")|res\.(send|json)\([^)]*(err|error)|printStackTrace|getStackTrace|traceback\.format_exc|\.stack[[:space:]]*[,)}]'
hits "raw exception or SQL passed into a template context" '(render|render_template|render_to_response|res\.render)\([^)]*(error|exception|exc|err|sql|query|message|traceback)'
hits "template variables that render internals" '\{[\{%][[:space:]]*=?[[:space:]]*(error|err|exception|exc|sql|sql_error|query|message|traceback|stack)' $TPL

printf '\n--- LOGGING ---\n'
hits "sensitive names inside a log/print call" "(log(ger|ging)?|print|console|System\\.out|fmt\\.Print|puts|NSLog)[^;]*($SENS)"
hits "whole request, body, or auth header logged" '(log|logger|print|console)[^;]*((request|req)\.(body|data|form|args|json|headers|POST|GET|cookies)|Authorization|Bearer|set-cookie)'
hits "request/response logging middleware" 'LoggingMiddleware|log_request|morgan\(|RequestLoggingFilter|CommonsRequestLoggingFilter|http_logger|axios.*interceptors'

printf '\n--- RESPONSE / SERIALIZATION LEAKAGE ---\n'
hits "whole-object serialization with no field allow-list" '\.__dict__|to_dict\(\)|model_to_dict\(|\.serialize\(\)|\.dict\(\)|vars\(|JSON\.stringify\([a-z_]+\)|fields[[:space:]]*=[[:space:]]*.__all__|exclude[[:space:]]*=[[:space:]]*\(\)'
hits "sensitive field names in a serializer or query projection" "(fields|columns|select|attributes|only|values)[[:space:]]*[:=][^;]*($SENS)"
hits "sensitive values rendered into markup" "\\{[\\{%][^}]*($SENS)|<input[^>]*hidden[^>]*($SENS)|<!--[^>]*($SENS)" $TPL

printf '\n--- STORAGE ---\n'
hits "weak or reversible password handling" 'md5|sha1\(|sha256\([^)]*pass|base64[^;]*pass|rot13|password[[:space:]]*==|encode\([^)]*pass'
hits "strong KDF present (absent = passwords unprotected)" 'bcrypt|argon2|scrypt|pbkdf2|make_password|password_hash\(|PasswordEncoder|Devise'
hits "sensitive column declared with no protection" "($SENS)[^;]*(Column|Field|VARCHAR|TEXT|String\\(|char\\()"
hits "world-writable or temp files holding data" 'chmod\([^)]*(0?777|0?666)|tempfile\.mktemp|os\.umask\(0\)|/tmp/'

printf '\n--- HEADERS / CACHING / TRANSPORT ---\n'
hits "Cache-Control / no-store (absent = PII cacheable by proxies)" 'Cache-Control|no-store|Pragma'
hits "Strict-Transport-Security (absent on HTTPS = downgrade)" 'Strict-Transport-Security|SECURE_HSTS_SECONDS|hsts'
hits "framework / version disclosure headers" 'X-Powered-By|X-AspNet-Version|expose_php|Server[[:space:]]*[:=][[:space:]]*.?(Apache|nginx|Express|Werkzeug)'

printf '\n--- DEBUG / ADMIN ROUTES ---\n'
hits "introspection routes" "(route|path|get|post|mapping)\\([^)]*$Q?/?(debug|status|health|metrics|actuator|env|config|phpinfo|trace|dump|_profiler|admin)"
hits "config or environment object handed out" 'app\.config|settings\.__dict__|os\.environ(\[|\.items|\.copy|\))|process\.env[[:space:]]*[,)}]|GetEnvironmentVariables|ConfigurationManager\.AppSettings'

printf '\n--- SETTINGS CONSTANTS (judge each name and value) ---\n'
hits "ALL_CAPS constant assigned a non-trivial string literal" "^[[:space:]]*[A-Z][A-Z0-9_]{3,}[[:space:]]*[:=][[:space:]]*$Q[^$Q]{6,}$Q" $CFG

printf '\n(end of sweep)\n'
exit 0
