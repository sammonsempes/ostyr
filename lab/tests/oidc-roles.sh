#!/usr/bin/env bash
# Usage: lab/tests/oidc-roles.sh <task-id> [mapped|unmapped]
# Logs in through oidc-login.sh, exchanges the code for tokens from the server VM (lab CA, client secret from oidc.env) and checks the roles claim
# of the ID token: the mapped user must hold ostyr-admins, the unmapped user no role. Prints the roles claim and "ok".
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"

task_id="${1:?usage: oidc-roles.sh <task-id> [mapped|unmapped]}"
user_kind="${2:-mapped}"
[[ "$user_kind" =~ ^(mapped|unmapped)$ ]] || die "user must be mapped or unmapped"
lab_state="$(state_dir "$task_id")"
read -r _ idp_user idp_address < <(awk '$1 == "zitadel"' "$lab_state/vms.txt")
read -r _ server_user server_address < <(awk '$1 == "server"' "$lab_state/vms.txt")
ssh_options=(-n -i "$lab_state/id_ed25519" -o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR)

login_output="$("$(dirname "${BASH_SOURCE[0]}")/oidc-login.sh" "$task_id" "$user_kind")"
code="$(sed -n 's/^code=//p' <<<"$login_output")"
verifier="$(sed -n 's/^code_verifier=//p' <<<"$login_output")"
oidc_env="$(ssh "${ssh_options[@]}" "$idp_user@$idp_address" "sudo cat /etc/ostyr-lab/oidc.env")"
client_id="$(sed -n 's/^OIDC_CLIENT_ID=//p' <<<"$oidc_env")"
client_secret="$(sed -n 's/^OIDC_CLIENT_SECRET=//p' <<<"$oidc_env")"
redirect_uri="$(sed -n 's/^OIDC_REDIRECT_URI=//p' <<<"$oidc_env")"
role_claim="$(sed -n 's/^OIDC_ROLE_CLAIM=//p' <<<"$oidc_env")"
role="$(sed -n 's/^OIDC_ROLE=//p' <<<"$oidc_env")"

response="$(ssh "${ssh_options[@]}" "$server_user@$server_address" "curl --silent --cacert /etc/ostyr-lab/ca.pem -u '$client_id:$client_secret' \
    --data-urlencode grant_type=authorization_code --data-urlencode 'code=$code' --data-urlencode 'redirect_uri=$redirect_uri' \
    --data-urlencode 'code_verifier=$verifier' https://zitadel.lab.test/oauth/v2/token")"
id_token="$(jq -r '.id_token // empty' <<<"$response")"
[[ -n "$id_token" ]] || die "no id_token in the token response: $response"
payload="$(cut -d. -f2 <<<"$id_token" | tr '_-' '/+')"
while ((${#payload} % 4)); do payload+="="; done
claims="$(base64 -d <<<"$payload")"
roles="$(jq -c --arg claim "$role_claim" '.[$claim] // {}' <<<"$claims")"
printf 'roles_claim=%s\n' "$roles"
if [[ "$user_kind" == "mapped" ]]; then
    jq -e --arg role "$role" 'has($role)' <<<"$roles" >/dev/null || die "mapped user lacks role $role"
else
    [[ "$roles" == "{}" ]] || die "unmapped user has roles: $roles"
fi
printf 'ok %s\n' "$user_kind"
