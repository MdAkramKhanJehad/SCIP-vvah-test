#!/bin/sh
# IaC misconfiguration sweep: inventories the manifest platforms present, then greps each one's known-bad directives.

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

flist() {
	label=$1
	pat=$2
	shift 2
	printf '\n== %s ==\n' "$label"
	out=$(grep -rElI $XD "$pat" "$@" "$ROOT" 2>/dev/null | sort || true)
	if [ -z "$out" ]; then
		echo "(none)"
	else
		printf '%s file(s); showing up to %s\n' "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" "$CAP"
		printf '%s\n' "$out" | head -n "$CAP"
	fi
}

nlist() {
	label=$1
	shift
	printf '\n== %s ==\n' "$label"
	out=$(find "$ROOT" \( -name .git -o -name node_modules -o -name vendor \) -prune -o \
		-type f \( "$@" \) -print 2>/dev/null | sort || true)
	if [ -z "$out" ]; then
		echo "(none)"
	else
		printf '%s file(s); showing up to %s\n' "$(printf '%s\n' "$out" | wc -l | tr -d ' ')" "$CAP"
		printf '%s\n' "$out" | head -n "$CAP"
	fi
}

echo "IAC MISCONFIGURATION SWEEP under: $ROOT"
echo "Candidates only. Cite file:line and the security property violated before reporting."

printf '\n--- MANIFEST INVENTORY (an absent platform is not a finding) ---\n'
flist "Terraform / HCL" '.' --include='*.tf' --include='*.tfvars' --include='*.hcl'
flist "Dockerfile / Containerfile" '^[[:space:]]*FROM[[:space:]]' --include='Dockerfile*' --include='Containerfile*' --include='*.dockerfile' --include='*.Dockerfile'
flist "Kubernetes / Helm manifests" '^[[:space:]]*apiVersion[[:space:]]*:' --include='*.yaml' --include='*.yml' --include='*.tpl'
flist "docker-compose" '^[[:space:]]*services[[:space:]]*:' --include='*.yml' --include='*.yaml'
flist "CI pipelines" '^[[:space:]]*(jobs|stages|pipelines)[[:space:]]*:|runs-on|pipeline[[:space:]]*\{' --include='*.yml' --include='*.yaml' --include='Jenkinsfile*' --include='*.jenkinsfile' --include='*.groovy'
flist "CloudFormation / SAM" 'AWSTemplateFormatVersion|Type[[:space:]]*:[[:space:]]*AWS::' --include='*.yaml' --include='*.yml' --include='*.json' --include='*.template'
flist "Ansible" '^[[:space:]]*-?[[:space:]]*(hosts|tasks|roles)[[:space:]]*:' --include='*.yml' --include='*.yaml'

printf '\n--- TERRAFORM / CLOUDFORMATION ---\n'
hits "wildcard IAM action / resource / principal" "(Action|Resource|Principal|actions|resources)$Q?[[:space:]]*[:=][[:space:]]*\[?[[:space:]]*$Q?\\*|:\\*$Q"
hits "open ingress (0.0.0.0/0, ::/0)" '0\.0\.0\.0/0|::/0'
hits "public buckets / instances" "acl[[:space:]]*=[[:space:]]*$Q(public-read|public-read-write|authenticated-read)|publicly_accessible[[:space:]]*=[[:space:]]*true|block_public_(acls|policy|access)[[:space:]]*=[[:space:]]*false|PublicAccessBlockConfiguration|AllUsers|AuthenticatedUsers"
hits "encryption off / absent" 'encrypted[[:space:]]*=[[:space:]]*false|storage_encrypted[[:space:]]*=[[:space:]]*false|server_side_encryption|enable_key_rotation[[:space:]]*=[[:space:]]*false|sse_algorithm'
hits "audit / logging config (absent = no trail)" 'cloudtrail|flow_log|access_logg?ing|enable_logging|logging_config'
hits "aws_ssm_parameter type (String leaks; want SecureString)" "aws_ssm_parameter|type[[:space:]]*=[[:space:]]*${Q}Secure?String"
hits "cross-account trust (check for ExternalId)" 'sts:AssumeRole|assume_role_policy|ExternalId'

printf '\n--- DOCKERFILE ---\n'
DF="--include=Dockerfile* --include=Containerfile* --include=*.dockerfile --include=*.Dockerfile"
hits "every USER directive (no hits at all = runs as root)" '^[[:space:]]*USER[[:space:]]' $DF
hits "every FROM (judge tag pinning; :latest or bare = unpinned)" '^[[:space:]]*FROM[[:space:]]' $DF
hits "remote fetch piped to a shell / ADD from URL" '(curl|wget)[^|]*\|[[:space:]]*(ba|z|da)?sh|^[[:space:]]*ADD[[:space:]]+https?://' $DF
hits "secret-shaped ENV / ARG (baked into image layers)" '^[[:space:]]*(ENV|ARG)[[:space:]]+[A-Za-z_]*(PASS|SECRET|TOKEN|KEY|CRED|AUTH)' $DF
hits "COPY of the whole build context (.git, .env leak)" '^[[:space:]]*COPY[[:space:]]+\.[[:space:]]+' $DF

printf '\n--- KUBERNETES / HELM / COMPOSE ---\n'
hits "privileged / privilege escalation / dangerous caps" 'privileged[[:space:]]*:[[:space:]]*true|allowPrivilegeEscalation[[:space:]]*:[[:space:]]*true|SYS_ADMIN|NET_ADMIN|NET_RAW|SYS_PTRACE|cap_add'
hits "runs as root" 'runAsUser[[:space:]]*:[[:space:]]*0|runAsNonRoot[[:space:]]*:[[:space:]]*false|runAsRoot|user[[:space:]]*:[[:space:]]*.?root'
hits "securityContext / readOnlyRootFilesystem (absent = unconstrained)" 'securityContext|readOnlyRootFilesystem'
hits "host namespace or host mount (escape path)" "hostNetwork|hostPID|hostIPC|hostPath|network_mode[[:space:]]*:[[:space:]]*$Q?host|pid[[:space:]]*:[[:space:]]*$Q?host|docker\\.sock|:[[:space:]]*/(proc|sys|etc|var/run)"
hits "plaintext secret material in a manifest" "kind[[:space:]]*:[[:space:]]*Secret|stringData|[A-Za-z_]*(PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY)[[:space:]]*:[[:space:]]*[^\$\\{[:space:]]"
hits "wildcard RBAC / cluster-admin" "cluster-admin|(resources|verbs|apiGroups)[[:space:]]*:[[:space:]]*\[?[[:space:]]*$Q?\\*|ClusterRoleBinding"
hits "internet-facing service type" 'type[[:space:]]*:[[:space:]]*(LoadBalancer|NodePort)'
hits "NetworkPolicy (absent = flat pod network)" 'kind[[:space:]]*:[[:space:]]*NetworkPolicy'

printf '\n--- CI / PIPELINE ---\n'
hits "pull_request_target / workflow_run (trusted context)" 'pull_request_target|workflow_run'
hits "untrusted event data interpolated into a step" '\$\{\{[[:space:]]*github\.event'
hits "third-party action pinned by mutable ref, not SHA" 'uses[[:space:]]*:[[:space:]]*[^[:space:]@]+@(v?[0-9][0-9a-z.-]*|main|master|latest|HEAD)[[:space:]]*$'
hits "secrets reaching a step" 'secrets\.[A-Z_]'
hits "self-hosted runner" 'runs-on[[:space:]]*:[[:space:]]*\[?[[:space:]]*.?self-hosted'
hits "shell interpolation in Jenkins / unpinned GitLab include" "(sh|bat)[[:space:]]+$Q[^$Q]*\\\$\\{|include[[:space:]]*:|remote[[:space:]]*:[[:space:]]*https?://"

GL="--include=.gitlab-ci.yml --include=*.gitlab-ci*.yml"
hits "GitLab job rules, which may skip the branch the approval gate covers" '^[[:space:]]*(rules|only|except)[[:space:]]*:' $GL

printf '\n--- ANSIBLE ---\n'
hits "shell/command with a templated variable" '(shell|command|raw)[[:space:]]*:.*\{\{'
hits "become / no_log" 'become[[:space:]]*:[[:space:]]*(yes|true)|no_log[[:space:]]*:[[:space:]]*(no|false)'
hits "vault-encrypted material" '\$ANSIBLE_VAULT;'
nlist "vault password / key file committed beside it" -name '*vault*pass*' -o -name '*vault*key*' -o -name '.vault_pass*'

printf '\n--- CROSS-CUTTING ---\n'
hits "TLS verification disabled" 'insecure_skip_verify|validate_certs[[:space:]]*:[[:space:]]*(no|false)|GIT_SSL_NO_VERIFY|NODE_TLS_REJECT_UNAUTHORIZED[[:space:]]*[:=][[:space:]]*.?0|sslverify[[:space:]]*[:=][[:space:]]*(false|0)|(curl|wget)[^|]*(--insecure|--no-check-certificate|[[:space:]]-k[[:space:]])'
hits "literal credential / connection string" "(access_key|secret_key|password|passwd|api_?key|auth_?token|private_key|connection_?string)[[:space:]]*[:=][[:space:]]*$Q[^$Q\$\\{][^$Q]{5,}"
hits "sample / default credentials" "(admin|root|changeme|letmein|password|secret|123456|postgres|guest)[[:space:]]*[:=][[:space:]]*$Q?(admin|root|changeme|letmein|password|secret|123456|postgres|guest)$Q?[[:space:]]*$"

printf '\n(end of sweep)\n'
exit 0
