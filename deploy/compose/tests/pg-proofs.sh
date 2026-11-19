#!/usr/bin/env bash
# Usage: docker compose exec -T postgres bash -s <pg-proofs.sh   (run by compose-lab.sh; the script executes inside the postgres container)
# Connects as the service role and prints one "key value" line per proof; the caller compares the values.
set -uo pipefail

readonly CONNECTION="host=postgres dbname=ostyr user=ostyr_service"
readonly VERIFY="sslmode=verify-full sslrootcert=/run/secrets/pg_ca"
PGPASSWORD="$(cat /run/pgtls/service_password)"
export PGPASSWORD
secure="$CONNECTION $VERIFY"

printf 'superuser %s\n' "$(psql "$secure" -At -c "select rolsuper from pg_roles where rolname = current_user")"
printf 'createrole %s\n' "$(psql "$secure" -At -c "select rolcreaterole from pg_roles where rolname = current_user")"
printf 'tls %s\n' "$(psql "$secure" -At -c "select ssl from pg_stat_ssl where pid = pg_backend_pid()")"
printf 'owner %s\n' "$(psql "$secure" -At -c "select pg_get_userbyid(datdba) from pg_database where datname = 'ostyr'")"
printf 'program %s\n' "$(psql "$secure" -At -c "copy (select 1) to program 'id > /tmp/pwned'" 2>&1 | grep -c 'must be superuser\|permission denied')"
printf 'pwned %s\n' "$(test -e /tmp/pwned && echo present || echo absent)"
printf 'readfile %s\n' "$(psql "$secure" -At -c "select pg_read_file('/run/pgtls/server.key')" 2>&1 | grep -c 'permission denied\|must be superuser')"
printf 'plain %s\n' "$(psql "$CONNECTION sslmode=disable" -At -c "select 1" 2>&1 | grep -c 'no encryption\|no pg_hba')"
printf 'otherdb %s\n' "$(psql "host=postgres dbname=postgres user=ostyr_service $VERIFY" -At -c "select 1" 2>&1 | grep -c 'no pg_hba')"
printf 'superlogin %s\n' "$(psql "host=postgres dbname=ostyr user=postgres $VERIFY" -At -c "select 1" 2>&1 </dev/null | grep -c 'no pg_hba')"
