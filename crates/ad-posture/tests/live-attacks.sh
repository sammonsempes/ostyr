#!/bin/bash
# Run in the lab VM with /tmp/ad_posture and /tmp/thresholds.yaml in place: hostile snapshots, each run prints the verdict and the peak RSS.
set -uo pipefail
DIR=$(mktemp -d)
EXAMPLE=/tmp/ad_posture
THRESHOLDS=/tmp/thresholds.yaml

python3 -c 'print("[" + ",".join(["{}"] * 1000000) + "]")' >"$DIR/entries.json"
python3 -c 'print("[{\"distinguishedName\":\"a\",\"memberOf\":[" + ",".join(["\"CN=g\""] * 1000000) + "]}]")' >"$DIR/values.json"
python3 -c 'import sys; sys.stdout.write("[{\"distinguishedName\":\"" + "a" * 104857600 + "\"}]")' >"$DIR/dn.json"
python3 -c 'import sys; sys.stdout.write("[{\"distinguishedName\":\"" + "a" * 20000000 + "\"}]")' >"$DIR/dn-within-cap.json"
printf '[{"distinguishedName":"CN=a\\u202eevil,DC=x"}]' >"$DIR/bidi.json"
printf '[{"distinguishedName":"CN=a\\nHigh Kerberoastable CN=fake,DC=x"}]' >"$DIR/newline.json"
printf '[{"distinguishedName":"CN=a","userAccountControl":"512"}]' >"$DIR/uac-string.json"
printf '[{"distinguishedName":"CN=a","userAccountControl":-512}]' >"$DIR/uac-negative.json"
printf '[{"distinguishedName":"CN=a","userAccountControl":4294967296}]' >"$DIR/uac-over.json"

for name in entries values dn dn-within-cap bidi newline uac-string uac-negative uac-over; do
    echo "== $name ($(stat -c %s "$DIR/$name.json") bytes)"
    /usr/bin/time -f "peak RSS %M KiB, %e s" "$EXAMPLE" "$DIR/$name.json" "$THRESHOLDS" 2>&1 | head -c 600
done
rm -rf "$DIR"
