# Ostyr platform with Docker Compose

One host runs the web interface (`web`, TLS port `9443`) in front of the platform API (`alerts`, `cases`, `cmdb`, `risk`) and its own PostgreSQL 16. The two containers talk over TLS, every secret is a file under `secrets/` (never in Git, never in an environment variable), and state lives in two named volumes: `pgdata` and `state` (accounts, audit log).

## Start

```sh
sudo ./init.sh ostyr.example.org
./build.sh
docker compose up -d
```

Run `docker compose up -d` from `deploy/compose` with no `COMPOSE_FILE`, `COMPOSE_PROFILES` or `-f`: the checks cover that command only.

- `init.sh <public-host-name>` runs once, as root: it creates `secrets/` (mode 0700) with a throwaway CA (its key is deleted after signing), the PostgreSQL and API certificates, a random PostgreSQL superuser password, a random password for the unprivileged service role `ostyr_service`, and the account store key. It never overwrites a file, so a rerun changes nothing. The host name goes into the API certificate; it may use `A-Z a-z 0-9 . -` only. To use your own API certificate, replace `secrets/api_tls.crt` and `secrets/api_tls.key` (the key owned by uid 65532, mode 0600); the service reloads it on change. A replaced `api_tls.crt` must still carry `DNS:platform` in its SAN and chain to `secrets/ca.crt`, or the web interface cannot reach the API.
- `build.sh` builds `ostyr-platform` and `ostyr-auth`, then the image `ostyr-platform:local` (distroless, user 65532) when Docker is present. Without Docker it leaves the build context in `target/deploy-compose/image`.
- Only the API's TLS port `8443`, the web interface's TLS port `9443` and the relay's agent port `7443` are published, on `0.0.0.0` explicitly (so host-local and IPv6 clients are not all folded into one gateway address and one login rate-limit bucket by `docker-proxy`); the compose network gives dynamic addresses from `172.29.63.128/25` only, so `.10` stays free for `web`. The web service runs the same image (`ostyr-web-ui`), serves TLS with the API certificate and key (`api_tls.*`, so browsers must trust `secrets/ca.crt`), reaches the API at `https://platform:8443` and is the only forwarder the platform trusts (`trusted_forwarders: 172.29.63.10`, the address compose pins for it). `init.sh` adds `DNS:platform` to the API certificate; on an older `secrets/` without it, `init.sh` warns and changes nothing: remove the TLS files to regenerate them. Sign in at `https://<host>:9443/login`. PostgreSQL has no published port and accepts `hostssl` connections from the service role `ostyr_service` to the database `ostyr` only (`config/pg_hba.conf`); the platform never holds the superuser password, which works on the in-container socket only. `config/pg-init-service-role.sh` creates the role (no superuser, no create-role, no create-database) as owner of the database on the first start.
- `deploy/compose` and its `secrets/` must be writable by root only, and so must the whole ancestor chain of the clone from `/` down (a clone under `/home/<user>` is refused, use for example `/srv/ostyr`): `init.sh` and the compose file run as root on this host, and the scripts and config mounted into the containers decide what runs there.

The CA certificate to trust on the clients is `secrets/ca.crt`: `curl --cacert secrets/ca.crt https://ostyr.example.org:8443/health`.

## First account

The account store is shared with the service through the `state` volume. The tool keeps its own audit log (`audit-cli.log`): the service holds the chain head of `audit.log`, so a second writer would break that chain. Commands are read from standard input:

```sh
read -r -s -p 'Passphrase: ' passphrase
printf 'bootstrap admin %s\n' "$passphrase" | docker compose run --rm -T platform /usr/local/bin/ostyr-auth \
    /var/lib/ostyr/accounts.json /var/lib/ostyr/audit-cli.log /run/secrets/store_key /etc/ostyr/compromised.txt
unset passphrase
```

`read -s` and the `printf` builtin keep the passphrase out of the shell history and the process list.

The output carries the TOTP secret to enrol in an authenticator. Other commands (`create`, `enrol`, `roles`) are listed by the tool's usage text.

## Agent path

Three more services carry the event path of an endpoint agent: `relay` (the only one with a published port, `7443`), `gateway` (`ostyr-event-gateway`, reachable from the relay only) and `nats` (NATS 2.15.2 with JetStream on the named volume `natsdata`, TLS, no published port, no monitoring port). An agent connects to `<host>:7443` with mutual TLS 1.3; the relay copies the bytes to the gateway (`172.29.63.11`), which checks the client certificate against `secrets/agent_ca.crt` and `config/revoked.yaml` and publishes each batch to `events.<tenant>`. `init.sh` also makes one proof agent certificate for tenant `default` and agent `lab-agent` (`secrets/agent.crt` and `secrets/agent.key`, signed by a throwaway agent CA whose key is deleted): replace `secrets/agent_ca.crt` with your own agent CA, restart `gateway`, and delete `agent.*` for real agents. An agent verifies the gateway with `secrets/ca.crt` and the name `gateway`.

NATS cannot declare a stream in a file: create it once, as the `admin` user of `secrets/nats_admin_password`, before the first agent connects (until then the gateway refuses every batch and the agent keeps its spool):

```sh
docker run --rm --network ostyr_default -v "$PWD/secrets/ca.crt:/ca.crt:ro" natsio/nats-box:0.19.7@sha256:ffce8bd103383f179f8c7f11cf645726acf5d17280706c530c3b342dbe16334c \
    nats --server tls://nats:4222 --tlsfirst --tlsca /ca.crt --user admin --password "$(sudo cat secrets/nats_admin_password)" \
    stream add events --subjects 'events.>' --storage file --retention limits --discard old --max-msgs=-1 --max-bytes=1073741824 --max-age=-1 \
    --max-msg-size=-1 --max-msgs-per-subject=-1 --dupe-window 2m --replicas 1 --no-allow-rollup --no-deny-delete --no-deny-purge
```

Read events back with the same container and `stream view events --raw` (add `-t` to `docker run`). The consumer services (siem-ingest, detection) are not in this stack yet.

## Configuration

The `playbooks` service (`ostyr-playbooks`, uid 65533, no published port) reads new alerts for tenant `default` from the database, runs the playbooks of `config/playbooks-notify.yaml` as a dry run and logs one line per round that found alerts (`docker compose logs playbooks`); nothing is executed. It has its own copy of the service password (`secrets/playbooks_pg_password`) and its own volume `playbooksstate`. Run one instance per tenant.

`config/` is mounted read-only at `/etc/ostyr` in the services: `web-ui.yaml` (web settings), `module.yaml` (modules and file paths), `pg.yaml` (PostgreSQL host, database, service user, its password file, CA), `risk-weights.yaml`, `compromised.txt`. The service watches these files: an edit on the host applies without a restart, except the start-only keys `settings.modules`, `settings.pg_settings` and `settings.risk.weights_file`, which need `docker compose restart platform`.

## Upgrade

Images are pinned by digest in `compose.yaml`. To upgrade, change the digest, then `docker compose pull` and `docker compose up -d`; for the platform, rerun `./build.sh` first. Migrations run when the platform starts.

## Backup

```sh
docker compose exec postgres pg_dump -U postgres ostyr >ostyr.sql
docker run --rm -v ostyr_state:/state -v "$PWD":/backup busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec tar -C /state -czf /backup/state.tar.gz .
```

Back up `secrets/` too, outside this host's Git checkout: without `store.key` the account store cannot be opened.

## Operations

The service role `ostyr_service` owns database `ostyr`, so a compromised module could set `ALTER DATABASE ostyr SET local_preload_libraries = ...` and lock every connection out. This is an accepted limit. Recovery, as the superuser on the in-container socket:

```sh
docker compose exec postgres psql -U postgres -d postgres -c 'ALTER DATABASE ostyr RESET ALL'
```

`init.sh` refuses a partly missing TLS set: remove `ca.crt`, `pg_server.*`, `api_tls.*`, `gateway_tls.*`, `nats_server.*`, `agent_ca.crt` and `agent.*` together to regenerate it (restart every service after; a `secrets/` made before the agent path existed is such a partial set).

## Tests

- `tests/static-test.sh`: static checks (compose config when Docker is installed, shellcheck, hardening greps).
- `tests/compose-lab.sh <task-id>`: the live proof in a booted `ubuntu-single` lab.
