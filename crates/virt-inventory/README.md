# ostyr-virt-inventory: deployer notes

`ostyr-virt-inventory <settings.yaml>` fetches one Proxmox cluster on a schedule and syncs it into one tenant's CMDB. The settings are described in the service file and the fetch file; this page covers stopping it.

## Stopping: how long the service can take

`SIGTERM` and `SIGINT` never cut a round. A database statement dropped by the client is not cancelled on the server, so it could commit after the process is gone with no audit record. The round in flight therefore runs to its end, then its audit record is written, then the service exits 0. A further interrupt during that time is logged by name (`a further interrupt is ignored`) and changes nothing.

The longest a stop can wait is `stop_bound_secs` (`src/stop_bound.rs`):

```
stop = ceil(timeout_ms / 1000) + connect_timeout_secs + pages x attempts x statements x cut
pages = ceil(limits.max_items / PAGE_OBSERVATIONS)
attempts = min(max_attempts, ATTEMPT_CEILING) x 2
statements = (max_assets / page_size + 1) + 2 x (max_child_rows / page_size + 1) + 1
cut = statement_timeout_secs x QUERY_WINDOWS + CLIENT_DEADLINE_MARGIN
```

`timeout_ms` is the fetch file's one deadline for both requests, `limits.max_items` its item cap, `connect_timeout_secs` and `statement_timeout_secs` come from the pg settings file, `max_assets` and `max_child_rows` from the service file (the cmdb defaults when absent), `page_size` and `max_attempts` are the cmdb defaults. `attempts` has a factor 2 because `apply_page` runs its attempts again without creations when the store refuses for a cap. `statements` counts the three keyset table reads of one attempt at their row caps, plus the one apply.

The constants this page relies on (a test compares each with the code, so a change of one fails until this page is updated):

- `QUERY_WINDOWS = 2`
- `CLIENT_DEADLINE_MARGIN_SECS = 5`
- `PAGE_OBSERVATIONS = 100`
- `ATTEMPT_CEILING = 10`
- `DEFAULT_PAGE_SIZE = 500`
- `DEFAULT_MAX_ASSETS = 10000`
- `DEFAULT_MAX_CHILD_ROWS = 200000`
- `DEFAULT_MAX_ATTEMPTS = 3`
- `DEFAULT_MAX_ITEMS = 10000`
- `DEFAULT_STATEMENT_TIMEOUT_SECS = 30`
- `DEFAULT_CONNECT_TIMEOUT_SECS = 5`

Worked example, a lab: `timeout_ms: 30000`, `max_items: 100`, `max_assets: 500`, `max_child_rows: 500`, `statement_timeout_secs: 10`, defaults otherwise. One page, 6 attempts, 2 + 2 + 2 + 1 = 7 statements, a cut of 25 s: 30 + 5 + 1 x 6 x 7 x 25 = 1085 s.

- `WORKED_LAB_SECS = 1085`

Worked example, the defaults: `timeout_ms: 30000`, 100 pages, 6 attempts, 21 + 2 x 401 + 1 = 824 statements, a cut of 65 s: 30 + 5 + 100 x 6 x 824 x 65 = 32136035 s.

- `WORKED_DEFAULT_SECS = 32136035`

That figure is a ceiling no supervisor can wait for. It is reached only when the database hangs on every statement of every attempt of every page; a healthy database ends a round in seconds.

### `TimeoutStopSec`

Set `TimeoutStopSec=` in the systemd unit to the bound of your configuration plus a margin when that bound is reasonable (the lab example: `TimeoutStopSec=1100`). With the defaults, choose the wait you accept (for example `TimeoutStopSec=300`) and lower `statement_timeout_secs` in the pg settings to shrink the ceiling; what the supervisor does after that time decides the outcome:

- A kill during the fetch phase (before the connect) orphans nothing: no statement has been sent, no row is written, the next round starts clean.
- A kill during the CMDB phase can orphan a statement: the server finishes it after the process is gone, the rows commit and there is no `virt.round` audit record for them. The next round reads the tenant again and reconciles, so the CMDB converges, but the audit trail has a gap for that round.
- A `SIGTERM` during start, while the connection and the migration run, skips the first round and exits 0, but a migration statement already sent can finish on the server after the exit (the migrations are idempotent and run again at the next start).

### The CA file

The CA of the Proxmox API is read at every round through a judged directory and file (`trusted.rs`): the file must be a regular file owned by root or the service user and closed to group and other writes, and its parent directory (an absolute, canonical path, each ancestor judged too) must be owned by the service user itself, not by root, and closed to group and other writes (`open_trusted_dir`): a CA in a root-owned directory is refused when the service runs as another user. A refusal names the failed check (`not a regular file`, `owned by neither root nor the service user`, `can be written by its group or by others`).
