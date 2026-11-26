# attack-paths

`ostyr-attack-paths <settings.yaml>` builds, every `interval_seconds`, the attack graph of each listed tenant from its latest `ad-posture` snapshot (JSON) and its manual tag file (YAML), searches the paths to the critical assets and stores one report per tenant in the `attack_paths` store, which `GET /attack-paths/reports` serves.

## Settings

`tenants` (each: `tenant`, `snapshot_file`, `tags_file`, absolute paths), `pg_settings` (the file too) and `audit_file` are read at start only: a reload that finds any of them changed is refused and audited `denied`. Restart the service to change them. `interval_seconds` (3 600 to 86 400), `deadline_seconds` (1 to 3 600), `max_depth` and `max_paths` are applied live on SIGHUP or when the file changes, and audited.

The snapshot and the tag file are overwritten in place by their producers and read once per round, through a handle checked as a regular file and under a size cap. A snapshot over a bound, a tag file over its cap or an unknown tag fails that tenant's round by name; the other tenants still run.

## Stopping the service

After the first SIGINT or SIGTERM the migration or the round in flight runs to its end and logs its line, then the service exits 0. A second signal is logged and ignored: nothing cuts a statement, so nothing commits after the process has exited.

The store phase of one round is bounded by this many seconds:

```
tenants (at most 100) x (2 x deadline_seconds + 5) + connect_timeout_secs
```

Each tenant is one store call, which sends two statements (Parse and Execute), each with its own `deadline_seconds`, and the client gives up 5 s after the second. Reading, building and searching the graph run before the statement and have no deadline of their own: the snapshot is at most 32 MiB and the search at most 10 000 000 steps.

An interrupt during the start waits for the connection and the schema migration, bounded by this many seconds, and then no round runs:

```
connect_timeout_secs + 5 x (2 x statement_timeout_secs + 5) + 3 x (3600 + 5)
```

`statement_timeout_secs` is the one in `pg_settings`. Set the supervisor's stop timeout above the larger of the two bounds plus the compute time, for example in the systemd unit:

```
TimeoutStopSec=<bound + compute time + 30>
```

A SIGKILL from the supervisor before the work ends is the one case that can leave a statement running in the database after the process is gone.
