# ostyr-intel: running the feed service

`ostyr-intel <settings.yaml>` polls the feeds of one tenant on a schedule and loads the indicators into ClickHouse.

## Settings

- `feeds_file` and `audit_file`: absolute paths. `interval_seconds`: 60 to 86 400.
- The feeds file is reloaded by `SIGHUP`; every reload is audited under the tenant `all`.
- `clickhouse.url`, `clickhouse.tenant`, `clickhouse.password_file`, `clickhouse.ca_file`, `clickhouse.database`, `clickhouse.table` and `clickhouse.dictionary` are read at start only: a reload that changes one is refused and audited `denied`; restart the service to change them.
- A file feed must be a regular file of at most 256 MiB, and a document feed (`json`, `stix`, `misp`) at most 64 MiB; a FIFO, a device or a symlink is a failed feed named in the round log, the other feeds still load.

## Bounds

- A file feed holds at most 100 000 IOCs; a list of a document (JSON array, STIX `objects`, MISP `Object`, `Attribute`, `Tag`) holds a counted number of entries: more is a failed feed named `too_many_iocs`, `too_many_objects` or `too_many_attributes`, nothing of it is kept, the other feeds load. A document that yields no IOC and no skip is warned as `empty_document`.
- The tenant's live rows are bounded at the writer: the RPZ read returns at most 250 000 network and domain rows, so before each round the service reads what the table already holds (live rows, expiry in the future) and leaves out, whole and named `stored_ioc_cap` with the live count, every feed that would take the tenant past 250 000 network and domain rows or 500 000 rows of all types. A TAXII feed left out keeps its cursor. The round warning `intel feeds left out: stored bound` names the feeds left out and the feeds holding the most live rows, whether or not they are still in the settings. Old rows leave the table by their TTL (`ttl_seconds`, 30 days by default): a feed whose values change every round needs a short `ttl_seconds`.
- A table already holding more than 250 000 network and domain rows (`stored_ioc_cap_exceeded`) admits no feed until the TTL drains it; to purge a feed by hand: `ALTER TABLE <database>.<table> DELETE WHERE tenant = '<tenant>' AND feed = '<feed>'`.
- A round whose stored rows cannot be read (`stored_count_unreadable: <reason>`) reads, polls and loads nothing, and keeps every cursor.
- One writer per (tenant, table): a second instance can pass the budget at the same time and the read then fails loud as `TooManyRows`.

## Stopping

- `SIGTERM` and `SIGINT` are seen between rounds. A round never stops with a database or HTTP statement in flight: it runs to its end, and a second signal is ignored.
- A round lasts at most the sum of the `timeout_ms` of each TAXII feed (default 30 s, at most 600 s) plus the `timeout_ms` of the ClickHouse load, plus the `timeout_ms` of the stored-rows read that opens the round, plus the local reading and parsing of the file feeds (a document is counted by a byte scan, then each element is parsed alone).
- Set `TimeoutStopSec` of the unit above that sum (for example 300 s with a few feeds at the default timeout). A shorter value makes systemd send `SIGKILL` while a statement may still be running; the server then finishes it unlogged. Rows are idempotent (`ReplacingMergeTree`), so a repeated load is harmless.
- Run one instance per tenant.
