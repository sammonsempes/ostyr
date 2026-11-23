"""Usage: python3 -I config-check.py <compose-dir> < config.json

Reads the output of `docker compose config --format json` on stdin and prints one `ok` or `FAIL` line per check; exits 1 on any failure.
"""
import json
import os
import sys

WEB = "web"
WEB_SECRETS = {"pg_ca", "api_tls_key", "api_tls_cert"}
WEB_TARGETS = {"/etc/ostyr", "/var/lib/ostyr"}
PUBLISHED = {("0.0.0.0", "8443", "8443"), ("0.0.0.0", "9443", "9443")}


def published_ports(services):
    return [
        (port.get("host_ip", ""), str(port.get("published", "")), str(port.get("target", "")))
        for service in services.values()
        for port in service.get("ports", [])
    ]


def inside(path, parent):
    return path == parent or path.startswith(parent.rstrip("/") + "/")


def forbidden_bind(source, compose_dir):
    real = os.path.realpath(os.path.join(compose_dir, source))
    secrets = os.path.realpath(os.path.join(compose_dir, "secrets"))
    return inside(secrets, real) or inside(real, secrets)


def web_binds(web):
    return [volume for volume in web.get("volumes", []) if volume.get("type") == "bind"]


def checks(config, compose_dir):
    services = config.get("services", {})
    web = services.get(WEB, {})
    volumes = web.get("volumes", [])
    return [
        ("published ports are exactly 0.0.0.0:8443->8443 and 0.0.0.0:9443->9443", sorted(published_ports(services)) == sorted(PUBLISHED)),
        ("no service sets network_mode", not any("network_mode" in service for service in services.values())),
        (
            "web binds neither the compose directory, the secrets directory nor a parent or child of it",
            not any(forbidden_bind(volume.get("source", ""), compose_dir) for volume in web_binds(web)),
        ),
        (
            "web mounts exactly its settings directory and its state volume",
            {volume.get("target") for volume in volumes} == WEB_TARGETS and len(volumes) == len(WEB_TARGETS),
        ),
        (
            "web holds exactly the three secrets pg_ca, api_tls_key and api_tls_cert",
            sorted(secret.get("source", "") for secret in web.get("secrets", [])) == sorted(WEB_SECRETS),
        ),
    ]


def main():
    results = checks(json.load(sys.stdin), os.path.realpath(sys.argv[1]))
    for description, passed in results:
        print(("ok   " if passed else "FAIL ") + description)
    return 0 if all(passed for _, passed in results) else 1


sys.exit(main())
