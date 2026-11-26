# ostyr-waf

`ostyr-waf <settings.yaml>` renders the routes file into Caddy's native JSON and loads it into the running Caddy. It reloads on a change of the routes or settings file and on `SIGHUP`, and exits 0 on `SIGTERM` or `SIGINT`.

## Settings

`routes_file`, `out_dir`, `admin_socket` and `audit_file` are plain absolute paths. `deadline_seconds` is 1 to 120 (default 30).

- `audit_file` must not be the settings file, the routes file or `<out_dir>/caddy.json` (the service refuses to start). On every delivery the open audit file is compared by device and inode with `caddy.json` and the other files the delivery creates in `out_dir`, and must have one link: a symlink, bind mount or hard link made at any time refuses that delivery (audited `denied`, the old configuration kept).
- Caddy must listen for its admin API on `admin_socket` (a Unix socket whose parent directory is 0700 and owned by the service user).

## Stopping

A signal received while a delivery is running never cuts it: the delivery finishes its audit record and its `caddy.json` first, then the service exits. A delivery is the validate step, the reload step and a read-back, each under `deadline_seconds`, so a stop can take up to three times that value when Caddy's admin socket hangs.

The unit file `packaging/ostyr-waf.service` sets:

- `KillMode=mixed`: only the main process receives `SIGTERM`; the default `control-group` also signals the `caddy validate` or `caddy reload` child, and the delivery in flight is then refused.
- `TimeoutStopSec=400`: above three times the largest `deadline_seconds` (120). With a smaller `deadline_seconds`, keep `TimeoutStopSec` above three times your value.

## Signals at start

`SIGHUP`, `SIGINT` and `SIGTERM` are registered before the settings are read, so none of them kills the process during start-up: they are queued and handled once the first delivery is audited and published. A refused or unknown first delivery is audited and exits 1.
