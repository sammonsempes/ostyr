#!/usr/bin/env bash
# Usage: lab-accounts.sh <admin-password> <analyst-password>   (run in the compose directory, as root, by compose-lab.sh inside the lab VM)
# Drives one ostyr-auth process through the shared account store: bootstraps an administrator, logs in, creates the four lab accounts and enrols their TOTP.
# The sessions live in the tool's memory, so one process serves every command. Creates an analyst, an auditor, a responder and a reader with the analyst password and prints one `<role> <TOTP secret>` line each.
set -euo pipefail

readonly ADMIN_PASSWORD="${1:?usage: lab-accounts.sh <admin-password> <analyst-password>}"
readonly ANALYST_PASSWORD="${2:?usage: lab-accounts.sh <admin-password> <analyst-password>}"
readonly TOOL=/usr/local/bin/ostyr-auth
readonly SOURCE=lab

reply=""

coproc SESSION { docker compose run --rm -T platform "$TOOL" /var/lib/ostyr/accounts.json /var/lib/ostyr/audit-cli.log /run/secrets/store_key /etc/ostyr/compromised.txt; }

send() {
    printf '%s\n' "$1" >&"${SESSION[1]}"
    read -r reply <&"${SESSION[0]}"
}

skip_line() {
    read -r _ <&"${SESSION[0]}"
}

secret_of() {
    printf '%s\n' "${reply#secret }"
}

send "bootstrap admin $ADMIN_PASSWORD"
skip_line
admin_secret="$(secret_of)"
send "totp $admin_secret"
admin_code="$reply"
send "login admin $ADMIN_PASSWORD $SOURCE $admin_code"
token="${reply#ok }"
for role in analyst auditor responder reader; do
    send "create $token $role $ANALYST_PASSWORD $role"
    [[ "$reply" == ok ]]
    send "enrol $token $role"
    skip_line
    printf '%s %s\n' "$role" "$(secret_of)"
done
input_fd="${SESSION[1]}"
exec {input_fd}>&-
