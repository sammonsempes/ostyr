"""Usage: python3 -I config-check.py <compose-dir> <golden.json> < config.json
       python3 -I config-check.py --print <compose-dir> < config.json

Reads `docker compose config --format json` on stdin, reduces it to a projection (every service field, bind sources and secret files resolved with
realpath and made relative to the compose directory) and compares it exactly to the committed golden file. Prints `ok` or `FAIL` plus the diff.
"""
import difflib
import json
import os
import sys

EQUAL = "the parsed configuration equals the committed projection"


def relative(path, compose_dir):
    return os.path.relpath(os.path.realpath(os.path.join(compose_dir, path)), compose_dir)


def project_service(service, compose_dir):
    projected = dict(service)
    projected["volumes"] = [
        dict(volume, source=relative(volume["source"], compose_dir)) if volume.get("type") == "bind" else volume
        for volume in service.get("volumes", [])
    ]
    return projected


def project(config, compose_dir):
    projected = {key: value for key, value in config.items() if key not in ("services", "secrets")}
    projected["services"] = {name: project_service(service, compose_dir) for name, service in config.get("services", {}).items()}
    projected["secrets"] = {
        name: dict(secret, file=relative(secret["file"], compose_dir)) if "file" in secret else secret
        for name, secret in config.get("secrets", {}).items()
    }
    return json.dumps(projected, indent=2, sort_keys=True) + "\n"


def main():
    if sys.argv[1] == "--print":
        sys.stdout.write(project(json.load(sys.stdin), os.path.realpath(sys.argv[2])))
        return 0
    actual = project(json.load(sys.stdin), os.path.realpath(sys.argv[1]))
    with open(sys.argv[2], encoding="ascii") as handle:
        expected = handle.read()
    if actual == expected:
        print("ok   " + EQUAL)
        return 0
    print("FAIL " + EQUAL)
    sys.stdout.writelines(difflib.unified_diff(expected.splitlines(True), actual.splitlines(True), "golden", "actual"))
    return 1


sys.exit(main())
