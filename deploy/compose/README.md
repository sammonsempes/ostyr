# Ostyr platform with Docker Compose

One host runs the platform API (`alerts`, `cases`, `cmdb`, `risk`) and its own PostgreSQL 16. The two containers talk over TLS, every secret is a file under `secrets/` (never in Git, never in an environment variable), and state lives in two named volumes: `pgdata` and `state` (accounts, audit log).

## Start

```sh
sudo ./init.sh ostyr.example.org
./build.sh
docker compose up -d
```

- `init.sh <public-host-name>` runs once, as root: it creates `secrets/` (mode 0700) with a throwaway CA (its key is deleted after signing), the PostgreSQL and API certificates, a random PostgreSQL password and the account store key. It never overwrites a file, so a rerun changes nothing. The host name goes into the API certificate; it may use `A-Z a-z 0-9 . -` only. To use your own API certificate, replace `secrets/api_tls.crt` and `secrets/api_tls.key` (the key owned by uid 65532, mode 0600); the service reloads it on change.
- `build.sh` builds `platform_api` and `auth_tool`, then the image `ostyr-platform:local` (distroless, user 65532) when Docker is present. Without Docker it leaves the build context in `target/deploy-compose/image`.
- Only the API's TLS port `8443` is published. PostgreSQL has no published port and accepts `hostssl` connections only (`config/pg_hba.conf`).

The CA certificate to trust on the clients is `secrets/ca.crt`: `curl --cacert secrets/ca.crt https://ostyr.example.org:8443/health`.

## First account

The account store is shared with the service through the `state` volume. The tool keeps its own audit log (`audit-cli.log`): the service holds the chain head of `audit.log`, so a second writer would break that chain. Commands are read from standard input:

```sh
echo 'bootstrap admin a-long-passphrase' | docker compose run --rm -T platform /usr/local/bin/auth_tool \
    /var/lib/ostyr/accounts.json /var/lib/ostyr/audit-cli.log /run/secrets/store_key /etc/ostyr/compromised.txt
```

The output carries the TOTP secret to enrol in an authenticator. Other commands (`create`, `enrol`, `roles`) are listed by the tool's usage text.

## Configuration

`config/` is mounted read-only at `/etc/ostyr`: `module.yaml` (modules and file paths), `pg.yaml` (PostgreSQL host, database, user, password file, CA), `risk-weights.yaml`, `compromised.txt`. The service watches these files: an edit on the host applies without a restart, except the start-only keys `settings.modules`, `settings.pg_settings` and `settings.risk.weights_file`, which need `docker compose restart platform`.

## Upgrade

Images are pinned by digest in `compose.yaml`. To upgrade, change the digest, then `docker compose pull` and `docker compose up -d`; for the platform, rerun `./build.sh` first. Migrations run when the platform starts.

## Backup

```sh
docker compose exec postgres pg_dump -U ostyr ostyr >ostyr.sql
docker run --rm -v ostyr_state:/state -v "$PWD":/backup busybox tar -C /state -czf /backup/state.tar.gz .
```

Back up `secrets/` too, outside this host's Git checkout: without `store.key` the account store cannot be opened.

## Tests

- `tests/static-test.sh`: static checks (compose config when Docker is installed, shellcheck, hardening greps).
- `tests/compose-lab.sh <task-id>`: the live proof in a booted `ubuntu-single` lab.
