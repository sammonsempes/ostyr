# Ostyr platform with Docker Compose

One host runs the platform API (`alerts`, `cases`, `cmdb`, `risk`) and its own PostgreSQL 16. The two containers talk over TLS, every secret is a file under `secrets/` (never in Git, never in an environment variable), and state lives in two named volumes: `pgdata` and `state` (accounts, audit log).

## Start

```sh
sudo ./init.sh ostyr.example.org
./build.sh
docker compose up -d
```

- `init.sh <public-host-name>` runs once, as root: it creates `secrets/` (mode 0700) with a throwaway CA (its key is deleted after signing), the PostgreSQL and API certificates, a random PostgreSQL superuser password, a random password for the unprivileged service role `ostyr_service`, and the account store key. It never overwrites a file, so a rerun changes nothing. The host name goes into the API certificate; it may use `A-Z a-z 0-9 . -` only. To use your own API certificate, replace `secrets/api_tls.crt` and `secrets/api_tls.key` (the key owned by uid 65532, mode 0600); the service reloads it on change.
- `build.sh` builds `platform_api` and `auth_tool`, then the image `ostyr-platform:local` (distroless, user 65532) when Docker is present. Without Docker it leaves the build context in `target/deploy-compose/image`.
- Only the API's TLS port `8443` is published. PostgreSQL has no published port and accepts `hostssl` connections from the service role `ostyr_service` to the database `ostyr` only (`config/pg_hba.conf`); the platform never holds the superuser password, which works on the in-container socket only. `config/pg-init-service-role.sh` creates the role (no superuser, no create-role, no create-database) as owner of the database on the first start.
- `deploy/compose` and its `secrets/` must be writable by root only, and so must the whole ancestor chain of the clone from `/` down (a clone under `/home/<user>` is refused, use for example `/srv/ostyr`): `init.sh` and the compose file run as root on this host, and the scripts and config mounted into the containers decide what runs there.

The CA certificate to trust on the clients is `secrets/ca.crt`: `curl --cacert secrets/ca.crt https://ostyr.example.org:8443/health`.

## First account

The account store is shared with the service through the `state` volume. The tool keeps its own audit log (`audit-cli.log`): the service holds the chain head of `audit.log`, so a second writer would break that chain. Commands are read from standard input:

```sh
read -r -s -p 'Passphrase: ' passphrase
printf 'bootstrap admin %s\n' "$passphrase" | docker compose run --rm -T platform /usr/local/bin/auth_tool \
    /var/lib/ostyr/accounts.json /var/lib/ostyr/audit-cli.log /run/secrets/store_key /etc/ostyr/compromised.txt
unset passphrase
```

`read -s` and the `printf` builtin keep the passphrase out of the shell history and the process list.

The output carries the TOTP secret to enrol in an authenticator. Other commands (`create`, `enrol`, `roles`) are listed by the tool's usage text.

## Configuration

`config/` is mounted read-only at `/etc/ostyr`: `module.yaml` (modules and file paths), `pg.yaml` (PostgreSQL host, database, service user, its password file, CA), `risk-weights.yaml`, `compromised.txt`. The service watches these files: an edit on the host applies without a restart, except the start-only keys `settings.modules`, `settings.pg_settings` and `settings.risk.weights_file`, which need `docker compose restart platform`.

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

`init.sh` refuses a partly missing TLS set: remove `ca.crt`, `pg_server.*` and `api_tls.*` together to regenerate it (restart both services after).

## Tests

- `tests/static-test.sh`: static checks (compose config when Docker is installed, shellcheck, hardening greps).
- `tests/compose-lab.sh <task-id>`: the live proof in a booted `ubuntu-single` lab.
