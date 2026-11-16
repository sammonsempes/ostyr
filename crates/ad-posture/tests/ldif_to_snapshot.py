"""Reads `ldbsearch` LDIF on stdin and writes the ad-posture snapshot (a JSON array) on stdout."""
import base64
import json
import sys

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
    json.dump([entry for entry in entries if "distinguishedName" in entry], sys.stdout)


main()
