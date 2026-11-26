# cert-inventory

`ostyr-certs <settings.yaml>` scans local certificate files on a schedule and stores them for one tenant.

## Stopping the service

After the first SIGINT or SIGTERM the round in flight runs to its end and logs its line, then the service exits 0. A second signal is logged and ignored: nothing cuts a round, so nothing commits after the process has exited.

The store phase of one round is bounded by this many seconds:

```
paths (at most 1000) x (2 x deadline_seconds + 5) + connect_timeout_secs
```

Each path is one `store_records` call, which sends two statements (Parse and Execute), each with its own `deadline_seconds` (1 to 3 600), and the client gives up 5 s after the second. `paths` is at most the scan's `max_files`, 1 000. The scan runs before any statement and has no deadline of its own (a hung mount holds it), so a supervisor kill during the scan leaves nothing running in the database. Set the supervisor's stop timeout above the store-phase bound plus your own scan time, for example in the systemd unit:

```
TimeoutStopSec=<paths x (2 x deadline_seconds + 5) + connect_timeout_secs + scan time + 30>
```

A SIGKILL from the supervisor before the round ends is the one case that can leave a statement running in the database after the process is gone. The same holds for the schema migration run at start: it is one transaction that core-pg lets finish on the server, so an interrupt during it may still commit after the process has exited.

## Settings

`tenant`, `pg_settings` (the file too), `audit_file` and `roots` are read at start only: a reload that finds any of them changed is refused and audited `denied`. Restart the service to change them.
