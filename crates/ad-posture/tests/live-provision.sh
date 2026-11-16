#!/bin/bash
# Run as root inside the lab VM: provisions a Samba AD DC with one planted weakness of each kind and writes the snapshot to /tmp/snapshot.json.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
SAM=/var/lib/samba/private/sam.ldb
PASSWORD='Lab-Passw0rd!x'

apt-get install -y samba winbind smbclient ldb-tools krb5-user python3
systemctl stop smbd nmbd winbind || true
systemctl disable smbd nmbd winbind || true
systemctl unmask samba-ad-dc
rm -f /etc/samba/smb.conf
samba-tool domain provision --use-rfc2307 --realm=LAB.TEST --domain=LAB --adminpass="$PASSWORD" --server-role=dc --dns-backend=SAMBA_INTERNAL
systemctl enable --now samba-ad-dc

samba-tool user create svc-roast "$PASSWORD"
samba-tool spn add http/web.lab.test svc-roast
samba-tool user create nopre "$PASSWORD"
ldbmodify -H "$SAM" <<EOF
dn: CN=nopre,CN=Users,DC=lab,DC=test
changetype: modify
replace: userAccountControl
userAccountControl: 4194816
EOF
samba-tool computer create srvdeleg
samba-tool delegation for-any-service 'srvdeleg$' on
ldbmodify -H "$SAM" <<EOF
dn: CN=srvdeleg,CN=Computers,DC=lab,DC=test
changetype: modify
replace: userAccountControl
userAccountControl: 528384
EOF
samba-tool user create clean "$PASSWORD"

ldbsearch -H "$SAM" '(|(objectClass=user)(objectClass=group))' dn objectClass sAMAccountName userAccountControl servicePrincipalName memberOf pwdLastSet \
    lastLogonTimestamp objectSid >/tmp/export.ldif
python3 /tmp/ldif_to_snapshot.py </tmp/export.ldif >/tmp/snapshot.json
wc -c /tmp/snapshot.json
