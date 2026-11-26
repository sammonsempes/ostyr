# cert-inventory

`ostyr-certs <settings.yaml>` scans local certificate files on a schedule and stores them for one tenant.

## Stopping the service

After the first SIGINT or SIGTERM the round in flight runs to its end and logs its line, then the service exits 0. A second signal is logged and ignored: nothing cuts a round, so nothing commits after the process has exited.

The longest stop is one round: the number of scanned paths times the statement deadline windows (`deadline_seconds`, up to 3 600 s each), plus the database connect timeout. Set the supervisor's stop timeout above your own bound, for example in the systemd unit:

```
TimeoutStopSec=<paths x deadline_seconds + connect_timeout_secs + 30>
```

A SIGKILL from the supervisor before the round ends is the one case that can leave a statement running in the database after the process is gone.

## Settings

`tenant`, `pg_settings` (the file too), `audit_file` and `roots` are read at start only: a reload that finds any of them changed is refused and audited `denied`. Restart the service to change them.
