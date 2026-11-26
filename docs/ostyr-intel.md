# ostyr-intel: running the feed service

`ostyr-intel <settings.yaml>` polls the feeds of one tenant on a schedule and loads the indicators into ClickHouse.

## Settings

- `feeds_file` and `audit_file`: absolute paths. `interval_seconds`: 60 to 86 400.
- The feeds file is reloaded by `SIGHUP`; every reload is audited under the tenant `all`.
- `clickhouse.url`, `clickhouse.tenant`, `clickhouse.password_file` and `clickhouse.ca_file` are read at start only: a reload that changes one is refused and audited `denied`; restart the service to change them.
- A file feed must be a regular file of at most 256 MiB; a FIFO, a device or a symlink is a failed feed named in the round log, the other feeds still load.

## Stopping

- `SIGTERM` and `SIGINT` are seen between rounds. A round never stops with a database or HTTP statement in flight: it runs to its end, and a second signal is ignored.
- A round lasts at most the sum of the `timeout_ms` of each TAXII feed (default 30 s, at most 600 s) plus the `timeout_ms` of the ClickHouse load, plus the local reading of the file feeds.
- Set `TimeoutStopSec` of the unit above that sum (for example 300 s with a few feeds at the default timeout). A shorter value makes systemd send `SIGKILL` while a statement may still be running; the server then finishes it unlogged. Rows are idempotent (`ReplacingMergeTree`), so a repeated load is harmless.
- Run one instance per tenant.
