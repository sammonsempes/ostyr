"""Reads `ldbsearch` LDIF on stdin and writes the ad-posture snapshot on stdout: {"captured": rootDSE currentTime, "entries": [...]}.

The LDIF holds the rootDSE block (`ldbsearch -s base -b "" currentTime`) besides the entries; without it `captured` is left out."""
import base64
import json
import sys
from datetime import datetime, timezone

NUMERIC = {"userAccountControl", "pwdLastSet", "lastLogonTimestamp"}
MULTI = {"objectClass", "servicePrincipalName", "memberOf"}


def folded(lines):
    joined = []
    for line in lines:
        if line.startswith(" ") and joined:
            joined[-1] += line[1:]
        else:
            joined.append(line)
    return joined


def value_of(name, raw, is_base64):
    text = base64.b64decode(raw).decode("utf-8") if is_base64 else raw
    return int(text) if name in NUMERIC else text


def entry_of(block):
    entry = {}
    for line in block:
        if line.startswith("#") or ":" not in line:
            continue
        name, _, rest = line.partition(":")
        is_base64 = rest.startswith(":")
        value = value_of(name, rest[1:].strip() if is_base64 else rest.strip(), is_base64)
        if name == "dn":
            entry["distinguishedName"] = value
        elif name in MULTI:
            entry.setdefault(name, []).append(value)
        else:
            entry[name] = value
    return entry


def rfc3339_of(generalized):
    moment = datetime.strptime(generalized.split(".")[0].rstrip("Z"), "%Y%m%d%H%M%S")
    return moment.replace(tzinfo=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def main():
    blocks, current = [], []
    for line in folded(sys.stdin.read().splitlines()):
        if line.strip() == "":
            blocks.append(current)
            current = []
        else:
            current.append(line)
    blocks.append(current)
    entries = [entry_of(block) for block in blocks]
    root = [entry for entry in entries if "currentTime" in entry]
    document = {}
    if root:
        document["captured"] = rfc3339_of(root[0]["currentTime"])
    document["entries"] = [entry for entry in entries if "distinguishedName" in entry and "currentTime" not in entry]
    json.dump(document, sys.stdout)


main()
