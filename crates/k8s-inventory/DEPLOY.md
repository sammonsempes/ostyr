# ostyr-k8s-inventory: stopping the service

Written for whoever writes the unit file.

## What a stop does

`SIGTERM` or `SIGINT` never cuts a round. The service finishes the fetch and the CMDB sync in flight (dropping a database client does not cancel the statement on the server, which would then commit after the exit with nothing logged), stops the file watch and the `SIGHUP` thread, waits for any reload in flight to write its audit record, then exits 0. A second interrupt is logged by name (`second interrupt ignored`) and changes nothing. `SIGKILL` is the only way to cut a round, and a statement already sent may still commit.

## How long it can take

One round is bounded, so the stop is bounded, by the sum of:

- the fetch: `timeout_ms` of the fetch settings, 300 000 ms at most (the run deadline across every list);
- the connection: `connect_timeout_secs` of the pg settings (default 5);
- the sync: every statement is cut at `statement_timeout_secs` (default 30, at most 3600); a page of 100 observations runs a few statements and retries a version conflict up to 10 times; the number of pages is the number of observations divided by 100, at most `max_assets` plus `max_child_rows` observations.

A healthy round ends in seconds. Set `TimeoutStopSec` above the worst case you accept, never below `timeout_ms / 1000 + connect_timeout_secs + statement_timeout_secs`; with the defaults `TimeoutStopSec=600` covers a round of a few dozen pages. A unit that kills the service earlier turns a stop into a cut round and can leave a partly synced CMDB, which the next round completes (a failed round logs `partly synced: pages=N created=... updated=...`).
