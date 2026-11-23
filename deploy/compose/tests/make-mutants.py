"""Usage: python3 -I make-mutants.py <compose.yaml> <output-dir> [file-prefix]

Writes one mutated copy of compose.yaml per attack on the published ports, the network mode and the web mounts, named <prefix><name>.yaml.
"""
import os
import sys

PLATFORM_PORT = '    ports:\n      - "0.0.0.0:8443:8443"\n'
WEB_SECRETS = "    secrets: [pg_ca, api_tls_key, api_tls_cert]\n"
WEB_VOLUMES = "      - webstate:/var/lib/ostyr\n"
PG_HBA_VOLUME = "      - ./config/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro\n"
POSTGRES_RESTART = "  postgres:\n    image:"


def with_platform_ports(replacement):
    return lambda text: replace_once(text, PLATFORM_PORT, replacement)


def with_web_volume(item):
    return lambda text: replace_once(text, WEB_VOLUMES, WEB_VOLUMES + "      - " + item + "\n")


def replace_once(text, old, new):
    if text.count(old) != 1:
        sys.exit("make-mutants: anchor not found exactly once: " + old.strip())
    return text.replace(old, new)


MUTANTS = {
    "dash_newline": with_platform_ports(PLATFORM_PORT + '      -\n        "5000:5000"\n'),
    "ports_space": with_platform_ports('    ports :\n      - "0.0.0.0:8443:8443"\n      - "5000:5000"\n'),
    "ports_dquote": with_platform_ports('    "ports":\n      - "0.0.0.0:8443:8443"\n      - "5000:5000"\n'),
    "ports_squote": with_platform_ports("    'ports':\n      - \"0.0.0.0:8443:8443\"\n      - \"5000:5000\"\n"),
    "ports_explicit": with_platform_ports('    ? ports\n    : ["0.0.0.0:8443:8443", "5000:5000"]\n'),
    "ports_flow": with_platform_ports('    ports: ["0.0.0.0:8443:8443", "5000:5000"]\n'),
    "port_unquoted": with_platform_ports(PLATFORM_PORT + "      - 5000:5000\n"),
    "port_long": with_platform_ports(PLATFORM_PORT + "      - target: 5000\n        published: 5000\n"),
    "pg_port": lambda text: replace_once(text, POSTGRES_RESTART, '  postgres:\n    ports:\n      - "5432:5432"\n    image:'),
    "network_mode_host": lambda text: replace_once(text, POSTGRES_RESTART, "  postgres:\n    network_mode: host\n    image:"),
    "web_mount_dot": with_web_volume(".:/srv/compose:ro"),
    "web_mount_dotdot": with_web_volume("./config/..:/srv/compose:ro"),
    "web_mount_parent": with_web_volume("..:/srv/parent:ro"),
    "web_mount_secrets": with_web_volume("./secrets:/srv/secrets:ro"),
    "webstate_named": lambda text: replace_once(text, "  webstate: {}\n", "  webstate: { name: ostyr_state }\n"),
    "webstate_named_block": lambda text: replace_once(text, "  webstate: {}\n", "  webstate:\n    name: ostyr_state\n"),
    "pg_ca_store_key": lambda text: replace_once(text, "    file: ./secrets/ca.crt\n", "    file: ./secrets/store.key\n"),
    "pg_publish_8443": lambda text: replace_once(
        replace_once(text, PLATFORM_PORT, ""), POSTGRES_RESTART, '  postgres:\n    ports:\n      - "0.0.0.0:8443:8443"\n    image:'
    ),
    "web_cap_add": lambda text: replace_once(text, WEB_SECRETS, WEB_SECRETS + "    cap_add: [SYS_ADMIN]\n"),
    "pg_bind_secrets": lambda text: replace_once(text, PG_HBA_VOLUME, PG_HBA_VOLUME + "      - ./secrets:/srv/secrets:ro\n"),
    "web_bind_etc": with_web_volume("/etc:/srv/etc:ro"),
    "web_secret_extra": lambda text: replace_once(text, WEB_SECRETS, "    secrets: [pg_ca, api_tls_key, api_tls_cert, store_key]\n"),
}


def main():
    source, output_dir = sys.argv[1], sys.argv[2]
    prefix = sys.argv[3] if len(sys.argv) > 3 else ""
    with open(source, encoding="ascii") as handle:
        text = handle.read()
    for name, mutate in MUTANTS.items():
        with open(os.path.join(output_dir, prefix + name + ".yaml"), "w", encoding="ascii") as out:
            out.write(mutate(text))


main()
