# Deploying `ostyr-grc`

`ostyr-grc <settings.yaml>` evaluates the configured compliance frameworks for one tenant on a schedule and stores each report in PostgreSQL. One process serves one tenant. The reports are read through the platform's `grc` module (`GET /grc/reports`).

## Settings file

```yaml
tenant: acme
pg_settings: /etc/ostyr/grc/pg.yaml
audit_file: /var/lib/ostyr/grc/audit.log
indicators_dir: /var/lib/ostyr/grc/indicators
manual_file: /etc/ostyr/grc/manual.yaml
frameworks: [builtin:nis2, builtin:iso27001-2022, /etc/ostyr/grc/internal.yaml]
interval_seconds: 3600
max_reports: 1000
```

- Start-only (a change is refused and audited as denied; restart to apply): `tenant`, `pg_settings`, `audit_file`, `indicators_dir`, `manual_file`, and the database host, port, database, user, password file and CA file inside `pg_settings`.
- Live (watched, validated, swapped atomically, audited under tenant `all`): `frameworks` and the framework files, the manual evidence file, `interval_seconds` (300 to 86 400), `max_reports` (1 to 1 000), the database timeouts. An applied change starts a round at once.
- `SIGHUP` reloads every file after the round in flight.
- `indicators_dir` holds one JSON array per producer (`*.json`, at most 16 files, each as the producer example prints it). A file that is absent, too large or malformed is refused alone and named in the log; the controls that need it read "no evidence" in the stored report.

## Stopping

`SIGTERM` and `SIGINT` never cut a round: the round in flight runs to its end (it stores or fails its report, and every outcome is logged), then the process exits 0. A second signal is logged and ignored.

The longest round is the connect timeout plus, for each framework (at most 8), three statements (last report, its body, the store), each bounded by twice the statement timeout plus a 5 second margin:

`stop bound = connect_timeout_secs + 24 x 2 x (statement_timeout_secs + 5)`

With the defaults (5 and 30 seconds) this is 1 685 seconds. Set the service unit's `TimeoutStopSec` to the bound of the values in `pg_settings` plus a minute, or lower `statement_timeout_secs` (10 seconds gives 725 seconds). A `SIGKILL` at the unit's timeout can leave a database statement committing after the process is gone, unlogged.

## Logs

Plain text on stderr. Log records of the PostgreSQL driver are dropped.
