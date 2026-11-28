# attack-paths

`ostyr-attack-paths <settings.yaml>` builds, every `interval_seconds`, the attack graph of each listed tenant from its latest `ad-posture` snapshot (JSON) and its manual tag file (YAML), searches the paths to the critical assets and stores one report per tenant in the `attack_paths` store, which `GET /attack-paths/reports` serves.

## Settings

`tenants` (each: `tenant`, `snapshot_file`, `tags_file`, absolute paths), `pg_settings` (the file too) and `audit_file` are read at start only: a reload that finds any of them changed is refused and audited `denied`. Restart the service to change them. `interval_seconds` (3 600 to 86 400), `deadline_seconds` (1 to 3 600), `max_depth` and `max_paths` are applied live on SIGHUP or when the file changes, and audited.

The snapshot and the tag file are read once per round through one handle opened without following a symlink (a link at the file name is refused), checked as a regular file, under a size cap, and the handle's size and times must be the same before and after the read, otherwise that tenant fails as `input_changed`. A producer must write a temporary file and rename it over the name. A snapshot over a bound, a tag file over its cap or an unknown tag fails that tenant's round by name; the other tenants still run. A snapshot cut by an in-place writer is caught when it no longer parses; one rewritten in place with fields of equal width is not detected, so the snapshot producer must replace the file by rename.

## Tag file

The tag file is YAML (`critical: [ids]`) followed by a trailer line that binds it to its content: `complete: sha256:` and the 64 lowercase hex digits of the SHA-256 of every byte before that line, then a newline (82 bytes). Write it with:

```
ostyr-attack-paths seal-tags [--reseal] /absolute/path/tags.yaml
```

`seal-tags` checks the body parses as tags, writes a temporary file next to the file (a `.tmp*` name, left behind only if the process dies before the rename, and never read by the service), and renames it over the name, keeping its mode without group or other write. It refuses a file that is a symlink, a FIFO or not a regular file, one that is group- or other-writable, a directory that is group- or other-writable or owned by neither you nor root, a file with a carriage return, a body without a final newline, a body that sealed would pass the runner's 8 MiB read cap, and a file that was replaced or edited between its read and the rename (nothing is written, run it again). A file that already ends with a `complete:` line needs `--reseal`: it prints `unchanged` and writes nothing if the digest still matches, otherwise `body changed since the last seal: N tags sealed`.

A file that is empty is refused; a file holding only the trailer (82 bytes) means no manual tags. A file cut or spliced by an in-place writer, edited after sealing, or with any carriage return fails that tenant as `input_incomplete`: a missing or malformed trailer says it may have been cut, a different digest says the file changed after it was sealed ("check the body, then run seal-tags --reseal"), and a carriage return says "CR line endings: write the file with LF". The digest checks integrity, it is not authentication: whoever can write the file or its directory decides the tags. Keep the file in Git byte for byte (`<file> -text` in the deployment repository's `.gitattributes`): a checkout that rewrites line endings, adds a BOM or runs a smudge filter fails that tenant loudly, as intended.

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
