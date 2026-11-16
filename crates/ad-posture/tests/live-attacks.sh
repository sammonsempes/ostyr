#!/bin/bash
# Run in the lab VM with /tmp/ad_posture and /tmp/thresholds.yaml in place: hostile snapshots, each run prints the verdict and the peak RSS.
set -uo pipefail
DIR=$(mktemp -d)
EXAMPLE=/tmp/ad_posture
THRESHOLDS=/tmp/thresholds.yaml
DA_SID=S-1-5-21-1-2-3-512

python3 -c 'print("[" + ",".join(["{}"] * 1000000) + "]")' >"$DIR/entries.json"
python3 -c 'print("[{\"distinguishedName\":\"a\",\"memberOf\":[" + ",".join(["\"CN=g\""] * 1000000) + "]}]")' >"$DIR/values.json"
python3 -c 'import sys; sys.stdout.write("[{\"distinguishedName\":\"" + "a" * 104857600 + "\"}]")' >"$DIR/dn.json"
python3 -c 'import sys; sys.stdout.write("[{\"distinguishedName\":\"" + "a" * 20000000 + "\"}]")' >"$DIR/dn-within-cap.json"
printf '[{"distinguishedName":"CN=a\\u202eevil,DC=x"}]' >"$DIR/bidi.json"
printf '[{"distinguishedName":"CN=a\\nHigh Kerberoastable CN=fake,DC=x"}]' >"$DIR/newline.json"
printf '[{"distinguishedName":"CN=a","userAccountControl":"512"}]' >"$DIR/uac-string.json"
printf '[{"distinguishedName":"CN=a","userAccountControl":-512}]' >"$DIR/uac-negative.json"
printf '[{"distinguishedName":"CN=a","userAccountControl":4294967296}]' >"$DIR/uac-over.json"
printf '[{"distinguishedName":"CN=Kim,DC=x"},{"distinguishedName":"CN=\\u212aim,DC=x"},{"distinguishedName":"CN=Kim,DC=x"}]' >"$DIR/kelvin-and-duplicate.json"
printf '[{"distinguishedName":"CN=Domain Admins\\u202e,CN=Users,DC=x","objectClass":["group"],"objectSid":"%s"},{"distinguishedName":"CN=u,DC=x","objectClass":["user"],"memberOf":["CN=Domain Admins,CN=Users,DC=x"],"userAccountControl":512}]' "$DA_SID" >"$DIR/da-unreadable.json"
printf '[{"distinguishedName":"CN=x | harmless | fix: none\\",DC=x","objectClass":["user"],"servicePrincipalName":["a/b"]}]' >"$DIR/pipe-quote.json"
python3 - "$DIR" <<'PY'
import sys
out = sys.argv[1]
cap = 33_554_432
values = ",".join(['"a"'] * 1000)
parts, size = [], 2
for i in range(100000):
    entry = '{"distinguishedName":"CN=' + str(i) + '","objectClass":[' + values + '],"servicePrincipalName":[' + values + '],"memberOf":[' + values + ']}'
    if size + len(entry) + 1 <= cap:
        parts.append(entry)
        size += len(entry) + 1
open(out + "/amplify.json", "w").write("[" + ",".join(parts) + "]")
pad = "x" * 990
parts, size = [], 2
for i in range(100000):
    entry = '{"distinguishedName":"CN=' + str(i).zfill(6) + pad + '","objectClass":["user"],"userAccountControl":4718592,"servicePrincipalName":["a/b"]}'
    if size + len(entry) + 1 <= cap:
        parts.append(entry)
        size += len(entry) + 1
open(out + "/many-findings.json", "w").write("[" + ",".join(parts) + "]")
PY

for name in entries values dn dn-within-cap bidi newline uac-string uac-negative uac-over kelvin-and-duplicate da-unreadable pipe-quote amplify many-findings; do
    echo "== $name ($(stat -c %s "$DIR/$name.json") bytes)"
    /usr/bin/time -f "peak RSS %M KiB, %e s, exit %x" "$EXAMPLE" "$DIR/$name.json" "$THRESHOLDS" 2>"$DIR/$name.err" >"$DIR/$name.out"
    head -c 700 "$DIR/$name.out"
    echo
    echo "lines=$(wc -l <"$DIR/$name.out") bytes=$(stat -c %s "$DIR/$name.out") $(tail -n 1 "$DIR/$name.err" | cut -c1-200)"
done
python3 -c '
import json, sys
lines = [json.loads(line) for line in open(sys.argv[1])]
print("pipe-quote parsed:", lines[0]["object"], "|", lines[0]["severity"], lines[0]["check"], "|", lines[-1])
' "$DIR/pipe-quote.out"
rm -rf "$DIR"
