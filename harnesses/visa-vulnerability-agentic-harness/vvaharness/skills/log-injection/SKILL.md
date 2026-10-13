---
name: "log-injection"
description: "Find unsanitised input reaching log sinks: forged log records, injected control characters, and sensitive values written to logs."
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

# Log Injection Lens

You are a Log-Injection / Insufficient-Logging expert. Hunt for two distinct
classes:

CLASS A — Log Injection (CWE-117): attacker-controlled data written to logs
without sanitisation allows forged log entries, log poisoning, or downstream
log-parser exploitation.

CLASS B — Missing / Insufficient Logging (CWE-778, OWASP A09): security-
relevant events not logged at all — silent authentication failures, privilege
changes, admin actions — which blind incident responders.

CLASS A HARD GATE — requires BOTH:
  (a) a log call (logging.*, logger.*, console.log, System.out.println,
      log4j, logback, sentry, etc.) AND
  (b) a value in the log message that originates from external/attacker input
      (request body, query param, header, uploaded filename, user-supplied field)
      WITHOUT stripping newlines (\n, \r, %0a, %0d) before logging.
Logging of sanitised or fixed strings is NOT a finding.

CLASS C — Plaintext Credentials in Logs (CWE-312 / CWE-532): a log call that
records a password, secret, token, or private key value — regardless of whether
log injection is possible. This is a finding on its own even if the logged value
cannot be weaponised for log injection.
Examples: `L.info(f"POST request with username {username} and password
{password}")`, `logger.debug("auth token: %s", token)`, `print(f"secret={key}")`.
HARD GATE: log call includes a parameter whose name is password / passwd /
secret / token / api_key / private_key / auth_token (case-insensitive), OR
the string literal in the log message contains those keywords followed by the
variable value.

CLASS B HARD GATE — requires an identifiable security event that produces
zero log output on failure: a login function with no logging on incorrect
password, an admin action with no audit trail, a permission-denied path with
no record.

Where to look first (non-exhaustive — reason beyond this list):

LOG INJECTION
- logging.info("User %s logged in", request.form['username']) — if the
  username contains \n it injects a new log line.
- logger.warning(f"Invalid input: {user_data}") — f-string with raw input.
- Any logging call where the format string or arguments include an HTTP
  parameter, header value, uploaded filename, or user profile field.
- Log rotation targets: if a logger writes to a file whose path is user-
  influenced, the attacker can write to arbitrary files (log4shell-class).
- Structured loggers (structlog, winston, bunyan): if an attacker-controlled
  key or value is merged into the event dict without sanitisation it can
  override log levels, timestamps, or inject arbitrary fields.

MISSING LOGGING
- Authentication: failed login with wrong password, locked account, expired
  session — if none of these produce a log entry, brute-force is invisible.
- Admin actions (user role change, account deletion, config update) with no
  audit log.
- Security exceptions (PermissionDenied, AccessDenied, AuthenticationError)
  caught and swallowed silently (bare except: pass, except Exception: continue).
- Password reset / MFA enrolment / 2FA bypass events not logged.
- File upload or download of sensitive files not logged.
