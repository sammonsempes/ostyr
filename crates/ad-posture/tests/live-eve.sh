#!/bin/bash
# Run as root in the lab VM after live-provision.sh: the unprivileged user eve, with create-child on one OU only, plants hostile objects.
set -euo pipefail
SAM=/var/lib/samba/private/sam.ldb
PASSWORD='Lab-Passw0rd!x'
BASE=DC=lab,DC=test
OU="OU=Helpdesk,$BASE"

samba-tool ou create "$OU" || true
samba-tool user create eve "$PASSWORD"
EVE_SID=$(ldbsearch -H "$SAM" '(sAMAccountName=eve)' objectSid | sed -n 's/^objectSid: //p')
samba-tool dsacl set --objectdn="$OU" --sddl="(A;CI;CCLC;;;$EVE_SID)" --car=create-child 2>/dev/null || samba-tool dsacl set --objectdn="$OU" --sddl="(A;CI;CCLC;;;$EVE_SID)"

add_as_eve() {
    ldbadd -H ldap://127.0.0.1 -U "eve%$PASSWORD" "$@"
}

BIDI=$(printf 'evil\xe2\x80\xaepc')
KELVIN=$(printf '\xe2\x84\xaaPC')
LONG=$(python3 -c 'print("c" * 2000)')

add_as_eve <<EOF
dn: CN=$BIDI,$OU
objectClass: user
EOF
add_as_eve <<EOF
dn: CN=KPC,$OU
objectClass: user
EOF
add_as_eve <<EOF
dn: CN=$KELVIN,$OU
objectClass: user
EOF
add_as_eve <<EOF
dn: CN=$LONG,$OU
objectClass: user
EOF
ldbsearch -H "$SAM" -b "$OU" '(objectClass=user)' dn | grep -c '^dn:'
