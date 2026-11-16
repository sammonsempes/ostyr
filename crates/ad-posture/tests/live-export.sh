#!/bin/bash
# Run as root in the lab VM: exports the Samba directory to /tmp/snapshot.json, runs the example now and 200 days ahead.
set -euo pipefail
SAM=/var/lib/samba/private/sam.ldb
ldbsearch -H "$SAM" '(|(objectClass=user)(objectClass=group))' dn objectClass sAMAccountName userAccountControl servicePrincipalName memberOf pwdLastSet \
    lastLogonTimestamp objectSid >/tmp/export.ldif
python3 /tmp/ldif_to_snapshot.py </tmp/export.ldif >/tmp/snapshot.json
wc -c /tmp/snapshot.json
echo "--- now"
/tmp/ad_posture /tmp/snapshot.json /tmp/thresholds.yaml
echo "exit=$?"
echo "--- now + 200 days"
/tmp/ad_posture /tmp/snapshot.json /tmp/thresholds.yaml $(($(date +%s) + 17280000)) | grep -c Critical
