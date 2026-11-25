"""Usage: python3 -I make-mutants.py <compose.yaml> <output-dir> [file-prefix]

Writes one mutated copy of compose.yaml per attack on the published ports, the network mode and the web mounts, named <prefix><name>.yaml.
"""
import os
import sys

PLATFORM_PORT = '    ports:\n      - "0.0.0.0:8443:8443"\n'
WEB_SECRETS = "    secrets: [pg_ca, api_tls_key, api_tls_cert]\n"
WEB_VOLUMES = "      - webstate:/var/lib/ostyr\n"
PG_HBA_VOLUME = "      - ./config/pg_hba.conf:/etc/postgresql/pg_hba.conf:ro\n"
WEB_SECOPT = '    security_opt: ["no-new-privileges:true"]\n'
WEB_COMMAND = '    command: ["/usr/local/bin/ostyr-web-ui"'
PG_CAPS = "    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID]\n"
PG_SECRETS = "    secrets: [pg_password, pg_service_password, pg_server_key, pg_server_cert, pg_ca]\n"
PLATFORM_COMMAND = '    command: ["/usr/local/bin/ostyr-platform", "/etc/ostyr/module.yaml"]\n'
PG_ENV = "      POSTGRES_PASSWORD_FILE: /run/secrets/pg_password\n"
POSTGRES_RESTART = "  postgres:\n    image:"
PROFILED_SERVICE = (
    "  debug:\n    image: ostyr-platform:local\n    profiles: [debug]\n    ports:\n"
    '      - "0.0.0.0:5002:5002"\n    volumes:\n      - ./secrets:/srv/secrets:ro\n'
)


PLAYBOOKS_SECRETS = "    secrets: [playbooks_pg_password, pg_ca]\n"
PLAYBOOKS_VOLUMES = "      - playbooksstate:/var/lib/ostyr-playbooks\n"
NATS_SECRETS = "    secrets: [nats_conf, nats_server_key, nats_server_cert]\n"
NATS_VOLUME = "      - natsdata:/data\n"
NATS_IMAGE = "    image: nats:2.15.2-scratch@sha256:965fc69c168a39f2bfd63a68361288beb0cc64ca60c8c308bf6c0eb74f463b1d\n"
GATEWAY_SECRETS = "    secrets: [pg_ca, gateway_tls_key, gateway_tls_cert, agent_ca, nats_gateway_password]\n"
GATEWAY_VOLUME = "      - gatewaystate:/var/lib/ostyr-gateway\n"
RELAY_VOLUME = "      - relaystate:/var/lib/ostyr-relay\n"
CH_IMAGE = "    image: clickhouse/clickhouse-server:26.8.46@sha256:%s\n"
CH_SECRETS = "    secrets: [clickhouse_server_key, clickhouse_server_cert, clickhouse_users]\n"
CH_VOLUME = "      - chdata:/var/lib/clickhouse\n"
CHSCHEMA_SECRETS = "    secrets: [pg_ca, clickhouse_schema_password]\n"
CHSCHEMA_VOLUME = "      - ./config/clickhouse-schema.sql:/etc/ostyr-schema/schema.sql:ro\n"
RELAY_PORT = '    ports:\n      - "0.0.0.0:7443:7443"\n'


SERVICE_SPAN = 400
DIGEST = "e49863ded96abdc0545bcd0320c1b99c979c18f27915eb6519a5546760d24cb9"


def replace_in_service(text, marker, old, new):
    start = text.index(marker)
    return text[:start] + replace_once(text[start : start + SERVICE_SPAN], old, new) + text[start + SERVICE_SPAN :]


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
    "profiled_service": lambda text: replace_once(text, "services:\n  postgres:\n", "services:\n" + PROFILED_SERVICE + "  postgres:\n"),
    "dollar_default": lambda text: replace_once(text, "ipv4_address: 172.29.63.10\n", "ipv4_address: ${WEB_IP:-172.29.63.10}\n"),
    "esc_secopt": lambda text: replace_once(text, WEB_SECOPT + WEB_COMMAND, '    security_opt: ["\\x24{WEB_SEC:-no-new-privileges:true}"]\n' + WEB_COMMAND),
    "esc_pgcmd": lambda text: replace_once(text, "      - ssl=on\n", '      - "\\x24{PG_SSL:-ssl=on}"\n'),
    "esc_tmpfs": lambda text: text.replace("      - /tmp\n", '      - "\\x24{TMP_DIR:-/tmp}"\n', 1),
    "env_passthrough": lambda text: replace_once(
        text, "    environment:\n      POSTGRES_PASSWORD_FILE: /run/secrets/pg_password\n", "    environment:\n      - POSTGRES_PASSWORD_FILE\n"
    ),
    "bin_capadd": lambda text: replace_once(
        text, PG_CAPS, "    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER, SETUID, !!binary JHtQR19DQVA6LVNFVEdJRH0=]\n"
    ),
    "bin_pgsecret": lambda text: replace_once(
        text, PG_SECRETS, "    secrets: [pg_password, pg_service_password, pg_server_key, pg_server_cert, !!binary JHtQR19TRUNSRVQ6LXBnX2NhfQ==]\n"
    ),
    "bin_platform_cmd": lambda text: replace_once(
        text, PLATFORM_COMMAND, '    command: ["/usr/local/bin/ostyr-platform", !!binary JHtQTEFURk9STV9DRkc6LS9ldGMvb3N0eXIvbW9kdWxlLnlhbWx9]\n'
    ),
    "flow_anchor": lambda text: replace_once(text, PG_CAPS, "    cap_add: [&cap CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID]\n"),
    "flow_alias": lambda text: replace_once(text, PG_CAPS, "    cap_add: [&cap CHOWN, DAC_OVERRIDE, FOWNER, SETUID, SETGID, *cap]\n"),
    "env_map_empty": lambda text: replace_once(text, PG_ENV, "      POSTGRES_PASSWORD_FILE:\n"),
    "env_map_tilde": lambda text: replace_once(text, PG_ENV, "      POSTGRES_PASSWORD_FILE: ~\n"),
    "env_map_null": lambda text: replace_once(text, PG_ENV, "      POSTGRES_PASSWORD_FILE: null\n"),
    "env_passthrough_sameindent": lambda text: replace_once(
        text, "    environment:\n      POSTGRES_PASSWORD_FILE: /run/secrets/pg_password\n", "    environment:\n    - PGOPTIONS\n"
    ),
    "volumes_sameindent": lambda text: replace_once(
        text,
        "    volumes:\n      - ./config:/etc/ostyr:ro\n      - webstate:/var/lib/ostyr\n",
        "    volumes:\n    - ./config:/etc/ostyr:ro\n    - webstate:/var/lib/ostyr\n    - ./secrets:/srv/secrets:ro\n",
    ),
    "entrypoint_moved": lambda text: replace_once(text, "      - postgres-entrypoint\n", '      - postgres-entrypoint\n        exec docker-entrypoint.sh "$$@"\n'),
    "playbooks_cap_add": lambda text: replace_once(text, PLAYBOOKS_SECRETS, PLAYBOOKS_SECRETS + "    cap_add: [SYS_ADMIN]\n"),
    "playbooks_secret_extra": lambda text: replace_once(text, PLAYBOOKS_SECRETS, "    secrets: [playbooks_pg_password, pg_ca, store_key]\n"),
    "playbooks_bind_secrets": lambda text: replace_once(text, PLAYBOOKS_VOLUMES, PLAYBOOKS_VOLUMES + "      - ./secrets:/srv/secrets:ro\n"),
    "playbooks_state_shared": lambda text: replace_once(text, PLAYBOOKS_VOLUMES, "      - state:/var/lib/ostyr-playbooks\n"),
    "playbooks_publish": lambda text: replace_once(text, PLAYBOOKS_SECRETS, PLAYBOOKS_SECRETS + '    ports:\n      - "0.0.0.0:7000:7000"\n'),
    "playbooks_root": lambda text: replace_once(text, "    user: 65533:65533\n", "    user: 0:0\n"),
    "nats_cap_add": lambda text: replace_once(text, NATS_SECRETS, NATS_SECRETS + "    cap_add: [SYS_ADMIN]\n"),
    "nats_publish": lambda text: replace_once(text, NATS_SECRETS, NATS_SECRETS + '    ports:\n      - "0.0.0.0:4222:4222"\n'),
    "nats_secret_extra": lambda text: replace_once(text, NATS_SECRETS, "    secrets: [nats_conf, nats_server_key, nats_server_cert, store_key]\n"),
    "nats_gateway_secret": lambda text: replace_once(text, NATS_SECRETS, "    secrets: [nats_conf, nats_server_key, nats_server_cert, nats_gateway_password]\n"),
    "nats_bind_secrets": lambda text: replace_once(text, NATS_VOLUME, NATS_VOLUME + "      - ./secrets:/srv/secrets:ro\n"),
    "nats_state_shared": lambda text: replace_once(text, NATS_VOLUME, "      - pgdata:/data\n"),
    "nats_unpinned": lambda text: replace_once(text, NATS_IMAGE, "    image: nats:2.15.2-scratch\n"),
    "nats_writable": lambda text: replace_once(text, NATS_IMAGE + "    restart: unless-stopped\n    read_only: true\n", NATS_IMAGE + "    restart: unless-stopped\n"),
    "gateway_cap_add": lambda text: replace_once(text, GATEWAY_SECRETS, GATEWAY_SECRETS + "    cap_add: [SYS_ADMIN]\n"),
    "gateway_publish": lambda text: replace_once(text, GATEWAY_SECRETS, GATEWAY_SECRETS + '    ports:\n      - "0.0.0.0:7443:7443"\n'),
    "gateway_secret_extra": lambda text: replace_once(
        text, GATEWAY_SECRETS, "    secrets: [pg_ca, gateway_tls_key, gateway_tls_cert, agent_ca, nats_gateway_password, store_key]\n"
    ),
    "gateway_nats_conf": lambda text: replace_once(
        text, GATEWAY_SECRETS, "    secrets: [pg_ca, gateway_tls_key, gateway_tls_cert, agent_ca, nats_gateway_password, nats_conf]\n"
    ),
    "gateway_bind_secrets": lambda text: replace_once(text, GATEWAY_VOLUME, GATEWAY_VOLUME + "      - ./secrets:/srv/secrets:ro\n"),
    "gateway_state_shared": lambda text: replace_once(text, GATEWAY_VOLUME, "      - state:/var/lib/ostyr-gateway\n"),
    "gateway_log_debug": lambda text: replace_once(text, "      RUST_LOG: info\n", "      RUST_LOG: debug\n"),
    "gateway_root": lambda text: replace_once(text, "    user: 65534:65534\n", "    user: 0:0\n"),
    "gateway_ip_moved": lambda text: replace_once(text, "ipv4_address: 172.29.63.11\n", "ipv4_address: 172.29.63.13\n"),
    "relay_cap_add": lambda text: replace_once(text, RELAY_PORT, RELAY_PORT + "    cap_add: [NET_BIND_SERVICE]\n"),
    "relay_secret_extra": lambda text: replace_once(text, RELAY_PORT, RELAY_PORT + "    secrets: [store_key]\n"),
    "relay_publish_extra": lambda text: replace_once(text, RELAY_PORT, RELAY_PORT + '      - "0.0.0.0:7444:7444"\n'),
    "relay_bind_secrets": lambda text: replace_once(text, RELAY_VOLUME, RELAY_VOLUME + "      - ./secrets:/srv/secrets:ro\n"),
    "relay_state_shared": lambda text: replace_once(text, RELAY_VOLUME, "      - gatewaystate:/var/lib/ostyr-relay\n"),
    "relay_root": lambda text: replace_once(text, "    user: 65531:65531\n", "    user: 0:0\n"),
    "relay_ip_moved": lambda text: replace_once(text, "ipv4_address: 172.29.63.12\n", "ipv4_address: 172.29.63.14\n"),
    "clickhouse_cap_add": lambda text: replace_once(text, CH_SECRETS, CH_SECRETS + "    cap_add: [SYS_ADMIN]\n"),
    "clickhouse_publish": lambda text: replace_once(text, CH_SECRETS, CH_SECRETS + '    ports:\n      - "0.0.0.0:8123:8123"\n'),
    "clickhouse_secret_extra": lambda text: replace_once(text, CH_SECRETS, "    secrets: [clickhouse_server_key, clickhouse_server_cert, clickhouse_users, store_key]\n"),
    "clickhouse_bind_secrets": lambda text: replace_once(text, CH_VOLUME, CH_VOLUME + "      - ./secrets:/srv/secrets:ro\n"),
    "clickhouse_state_shared": lambda text: replace_once(text, CH_VOLUME, "      - pgdata:/var/lib/clickhouse\n"),
    "clickhouse_unpinned": lambda text: replace_in_service(text, "  clickhouse:\n", CH_IMAGE % DIGEST, "    image: clickhouse/clickhouse-server:26.8.46\n"),
    "clickhouse_root": lambda text: replace_once(text, "    user: 101:101\n", "    user: 0:0\n"),
    "clickhouse_writable": lambda text: replace_in_service(text, "  clickhouse:\n", "    read_only: true\n", ""),
    "chschema_cap_add": lambda text: replace_once(text, CHSCHEMA_SECRETS, CHSCHEMA_SECRETS + "    cap_add: [SYS_ADMIN]\n"),
    "chschema_secret_extra": lambda text: replace_once(text, CHSCHEMA_SECRETS, "    secrets: [pg_ca, clickhouse_schema_password, clickhouse_users]\n"),
    "chschema_bind_secrets": lambda text: replace_once(text, CHSCHEMA_VOLUME, CHSCHEMA_VOLUME + "      - ./secrets:/srv/secrets:ro\n"),
    "chschema_anonymous_volume": lambda text: replace_once(text, "      - /var/lib/clickhouse\n", ""),
    "chschema_root": lambda text: replace_once(text, "    user: 65530:65530\n", "    user: 0:0\n"),
    "chschema_image_other": lambda text: replace_in_service(text, "  chschema:\n", CH_IMAGE % DIGEST, CH_IMAGE % ("0" * 64)),
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
