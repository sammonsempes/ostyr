# ostyr-k8s-inventory: stopping the service

Written for whoever writes the unit file.

## What a stop does

`SIGTERM` or `SIGINT` never cuts a round. The service finishes the fetch and the CMDB sync in flight (dropping a database client does not cancel the statement on the server, which would then commit after the exit with nothing logged), stops the file watch and the `SIGHUP` thread, waits for any reload in flight to write its audit record, then exits 0. A second interrupt is logged by name (`second interrupt ignored`) and changes nothing. `SIGKILL` is the only way to cut a round, and a statement already sent may still commit.

## How long it can take

One round is bounded, and so is the stop, but the bound is far above any real round. The worst case of one round is:

TimeoutStopSec >= timeout_ms / 1000 + connect_timeout_secs + pages x 2 x max_attempts x statements x (2 x statement_timeout_secs + 5)

- `timeout_ms / 1000`: the fetch, one deadline across every list (default 60 000 ms, at most 300 000).
- `connect_timeout_secs`: the pg connection (default 5).
- pages = 2 x max_total_items / 100, rounded up: pods and nodes are two lists of at most `max_total_items` each (default 20 000, ceiling 200 000), and the sync applies 100 observations a page.
- 2 x max_attempts: a page is retried on a version conflict up to `max_attempts` times (3; the store's ceiling of 10 is not reachable from the settings), and a page refused at a cap runs once more without creations.
- statements = (max_assets / page_size + 1) + 2 x (max_child_rows / page_size + 1) + 1, with page_size 500: each attempt reloads the whole tenant (assets, keys, attributes, by pages of 500) then applies the page in one statement.
- 2 x statement_timeout_secs + 5: one statement is cut by the server at `statement_timeout_secs` per protocol message (two windows) and by the client 5 s later (default 30, at most 3600).

At the defaults (400 pages, max_attempts 3, 824 statements, 30 s) the bound is 128544065 s. At the ceilings (4000 pages, statement_timeout_secs 3600) the bound is 142486083900 s.

Both are far above an hour, so no short `TimeoutStopSec` is safe for the worst case.  in seconds to minutes. Set `TimeoutStopSec=infinity` and stop a stuck unit by hand. Residual: a database that answers every statement just before its cut keeps a stop waiting for as long as it does; an operator who then sends `SIGKILL` (`systemctl kill`) cuts a round mid-statement, a statement already sent may still commit, and the next round completes the sync (a failed round logs `partly synced: pages=N created=... updated=...` or `the CMDB may hold the failed page or not`).

## How long the start can take

A stop asked while the service starts waits for the start (the interrupt is looked at between rounds, so the first round is then skipped): the migrations of the CMDB store run before the first round and a stop never cuts them. The worst case of the start is:

start >= connect_timeout_secs + (migrations + 4) x (2 x statement_timeout_secs + 5) + (1 + migrations x (migrations + 1)) x (max(statement_timeout_secs, 3600) + 5)

migrations = 6 (the embedded CMDB migrations)

- `connect_timeout_secs`: the pg connection (default 5).
- (migrations + 4) reads: the isolation, shape and search-path reads, the applied-versions read, and one more applied-versions read per retry, each cut like a round statement.
- 1 + migrations x (migrations + 1) scripts: the bootstrap script (it waits for the migration lock) plus at most migrations + 1 passes of at most `migrations` migrations (a unique violation is retried once per migration, and only when another process made progress), each script cut at the larger of `statement_timeout_secs` and 3600 s, plus 5 s.

At the defaults (connect_timeout_secs 5, statement_timeout_secs 30) the start bound is 155670 s. At the ceilings (both 3600) the start bound is 230665 s.

Both are far above an hour, so the advice is the same: `TimeoutStopSec=infinity`. In practice the start is seconds, and a start that waits long is waiting for another process's migration lock.
