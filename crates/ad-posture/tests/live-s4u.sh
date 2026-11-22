#!/bin/bash
# Run as root in the lab VM after live-provision.sh and the planted users: S4U2Self for an old account with a machine keytab, then lastLogonTimestamp read back.
set -uo pipefail
SAM=/var/lib/samba/private/sam.ldb
export KRB5_CONFIG=/tmp/s4u-krb5.conf
printf '[libdefaults]\n default_realm = LAB.TEST\n dns_lookup_kdc = false\n rdns = false\n[realms]\n LAB.TEST = {\n  kdc = 127.0.0.1\n }\n' >"$KRB5_CONFIG"
export KRB5CCNAME=/tmp/s4u.ccache
USER_NAME="${1:-old46}"

read_logon() {
    ldbsearch -H "$SAM" "(sAMAccountName=$USER_NAME)" lastLogonTimestamp lastLogon | grep -E '^(lastLogonTimestamp|lastLogon):' || echo "no lastLogon attributes"
}

echo "before:"
read_logon
samba-tool domain exportkeytab /tmp/dc.keytab --principal='UBUNTU$'
kinit -k -t /tmp/dc.keytab 'UBUNTU$@LAB.TEST'
kvno -U "$USER_NAME" -k /tmp/dc.keytab 'UBUNTU$@LAB.TEST'
echo "kvno exit=$?"
sleep 2
echo "after:"
read_logon
