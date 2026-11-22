#!/bin/bash
# Run in the lab VM after live-provision.sh with /tmp/ad_inactive_indicator in place: hostile snapshots for the inactive-accounts indicator, one verdict each.
set -uo pipefail
DIR=$(mktemp -d)
EXAMPLE=/tmp/ad_inactive_indicator
SNAPSHOT=/tmp/snapshot.json

variant() {
    python3 - "$SNAPSHOT" "$DIR/$1.json" "$2" <<'PY'
import copy, json, sys
source, target, kind = sys.argv[1:4]
document = json.load(open(source))
entries = document["entries"]
users = [e for e in entries if "user" in e.get("objectClass", []) and "computer" not in e.get("objectClass", [])]
now = __import__("datetime").datetime.now(__import__("datetime").timezone.utc)
stamp = lambda hours: (now - __import__("datetime").timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
captured_unix = int(__import__("datetime").datetime.strptime(document["captured"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=__import__("datetime").timezone.utc).timestamp())
ft = lambda unix: (unix + 11644473600) * 10**7
if kind == "bare":
    document = entries
elif kind == "empty":
    document = []
elif kind == "no-class":
    for e in entries:
        e.pop("objectClass", None)
elif kind == "no-domain-object":
    document["entries"] = [e for e in entries if "domainDNS" not in e.get("objectClass", [])]
elif kind == "no-rid500":
    document["entries"] = [e for e in entries if not e.get("objectSid", "").endswith("-500")]
elif kind == "year9999":
    next(e for e in users if e.get("sAMAccountName") == "fresh10")["lastLogonTimestamp"] = 2650467743999999999
elif kind == "after-capture":
    next(e for e in users if e.get("sAMAccountName") == "fresh10")["lastLogonTimestamp"] = ft(captured_unix + 60)
elif kind == "captured-old":
    document["captured"] = stamp(49)
elif kind == "captured-future":
    document["captured"] = stamp(-1)
elif kind == "captured-edge-year":
    document["captured"] = "9999-12-31T23:00:00-02:00"
elif kind == "unreadable":
    entries.append({"distinguishedName": "CN=evil‮pc,OU=Helpdesk,DC=lab,DC=test", "objectClass": ["top", "user"]})
elif kind == "names":
    next(e for e in users if e.get("sAMAccountName") == "clean")["sAMAccountName"] = "evil\x1bname"
    next(e for e in users if e.get("sAMAccountName") == "nopre")["sAMAccountName"] = "n" * 10240
json.dump(document, open(target, "w"))
PY
}

run() {
    local name="$1"
    shift
    variant "$name" "$name"
    echo "--- $name"
    "$EXAMPLE" "$DIR/$name.json" lab1 "$@"
    echo "exit=$?"
}

for name in bare empty no-class no-domain-object no-rid500 year9999 after-capture captured-old captured-future captured-edge-year unreadable names; do
    run "$name"
done
echo "--- now 47 hours off"
variant plain plain
"$EXAMPLE" "$DIR/plain.json" lab1 "$(( $(date +%s) - 169200 ))"
echo "exit=$?"
echo "--- now 4 minutes off (accepted)"
"$EXAMPLE" "$DIR/plain.json" lab1 "$(( $(date +%s) + 240 ))"
echo "exit=$?"
echo "--- tenant -x"
"$EXAMPLE" "$DIR/plain.json" -x
echo "exit=$?"
