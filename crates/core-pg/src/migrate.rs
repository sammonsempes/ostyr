use crate::error::reduce;
use crate::error::PgError;
use crate::query::{column_text, execute_script, global_query, timed_script, timeout_millis};
use crate::settings::MAX_DEADLINE_SECS;
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio::time::{timeout, Instant};
use tokio_postgres::Client;
use tracing::info;


pub const MIGRATION_DEADLINE: Duration = Duration::from_secs(MAX_DEADLINE_SECS);


pub const MIGRATION_CLIENT_MARGIN: Duration = Duration::from_secs(5);


pub const MIGRATION_LOCK_KEY: i64 = 7_021_103_100;


pub const PAIR: usize = 2;


pub const MAX_VERSION_BYTES: usize = 64;


pub const MAX_APPLIED_ROWS: usize = 10_000;


/// Validates the namespace itself; one row past the cap is read so that an overflow is refused, never truncated.
pub fn applied_sql(namespace: &str) -> Result<String, PgError> {
    check_namespace(namespace)?;
    Ok(format!(
        "SELECT namespace, version, digest FROM public.schema_migrations WHERE namespace OPERATOR(pg_catalog.=) '{namespace}' ORDER BY version LIMIT {}",
        MAX_APPLIED_ROWS + 1
    ))
}


pub const COLUMNS_SQL: &str =
    "SELECT column_name::pg_catalog.text FROM information_schema.columns WHERE table_schema OPERATOR(pg_catalog.=) 'public' \
     AND table_name OPERATOR(pg_catalog.=) 'schema_migrations'";


pub const ISOLATION_SQL: &str = "SHOW default_transaction_isolation";


pub const REQUIRED_ISOLATION: &str = "read committed";


pub const DIGEST_COLUMN: usize = 2;


pub const MAX_NAMESPACE_BYTES: usize = 32;


pub const NAMESPACE_COLUMN: &str = "namespace";


pub const REQUIRED_SEARCH_PATH: &str = "search_path=pg_catalog, public, pg_temp";


pub const MAX_NAMED_FUNCTIONS: usize = 20;


pub const MAX_SIGNATURE_CHARS: usize = 128;


pub const MAX_ROW_CHARS: usize = 256;


pub const CUT_MARKER: &str = "…";


/// Bounds a text expression to `MAX_ROW_CHARS` characters on the server, a cut ending with `CUT_MARKER`, every name `pg_catalog`-qualified.
pub fn cut_sql(expression: &str) -> String {
    format!(
        "CASE WHEN pg_catalog.char_length({expression}) OPERATOR(pg_catalog.>) {max} \
         THEN pg_catalog.left({expression}, {keep}) OPERATOR(pg_catalog.||) '{CUT_MARKER}' ELSE {expression} END",
        max = MAX_ROW_CHARS,
        keep = MAX_ROW_CHARS - 1
    )
}


/// Functions of `public` outside other roles' extensions, every name `pg_catalog`-qualified so a planted `public.unnest` cannot answer.
pub fn functions_sql() -> String {
    format!(
        "SELECT {signature}, {setting} \
         FROM pg_catalog.pg_proc p WHERE p.pronamespace OPERATOR(pg_catalog.=) 'public'::pg_catalog.regnamespace \
         AND p.prokind OPERATOR(pg_catalog.=) ANY (ARRAY['f'::pg_catalog.\"char\", 'p'::pg_catalog.\"char\"]) \
         AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_extension x ON x.oid OPERATOR(pg_catalog.=) d.refobjid \
         WHERE d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.objid OPERATOR(pg_catalog.=) p.oid \
         AND d.refclassid OPERATOR(pg_catalog.=) 'pg_catalog.pg_extension'::pg_catalog.regclass \
         AND d.deptype OPERATOR(pg_catalog.=) 'e'::pg_catalog.\"char\" \
         AND x.extowner OPERATOR(pg_catalog.<>) (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname OPERATOR(pg_catalog.=) current_user)) \
         ORDER BY 1 LIMIT {limit}",
        signature = cut_sql("p.oid::pg_catalog.regprocedure::pg_catalog.text"),
        setting =
            cut_sql("coalesce((SELECT s FROM pg_catalog.unnest(p.proconfig) AS s WHERE pg_catalog.starts_with(s, 'search_path=') LIMIT 1), '')"),
        limit = MAX_APPLIED_ROWS + 1
    )
}


/// The record table as found in the database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TableShape {
    Absent,
    Legacy,
    Namespaced,
}


/// An ordered SQL file embedded with `include_str!`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Migration {
    pub version: &'static str,
    pub sql: &'static str,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedMigration {
    pub version: String,
    pub digest: String,
}


pub fn digest_of(sql: &str) -> String {
    format!("{:x}", Sha256::digest(sql.as_bytes()))
}


/// A namespace is `[a-z][a-z0-9_]{0,31}`: it is interpolated into the migration scripts, so nothing else may pass.
pub fn check_namespace(namespace: &str) -> Result<(), PgError> {
    let valid = namespace.chars().next().is_some_and(|first| first.is_ascii_lowercase())
        && namespace.len() <= MAX_NAMESPACE_BYTES
        && namespace
            .chars()
            .all(|character| character.is_ascii_digit() || character.is_ascii_lowercase() || character == '_');
    if valid {
        Ok(())
    } else {
        Err(PgError::InvalidNamespace {
            namespace: namespace.chars().take(MAX_NAMESPACE_BYTES).collect(),
        })
    }
}


pub fn table_shape(columns: &[String]) -> TableShape {
    if columns.is_empty() {
        TableShape::Absent
    } else if columns.iter().any(|column| column == NAMESPACE_COLUMN) {
        TableShape::Namespaced
    } else {
        TableShape::Legacy
    }
}


pub fn check_not_legacy(shape: TableShape) -> Result<(), PgError> {
    match shape {
        TableShape::Legacy => Err(PgError::LegacyRecords),
        TableShape::Absent | TableShape::Namespaced => Ok(()),
    }
}


pub fn check_version(version: &str) -> Result<(), PgError> {
    let valid = !version.is_empty()
        && version.len() <= MAX_VERSION_BYTES
        && version
            .chars()
            .all(|character| character.is_ascii_digit() || character.is_ascii_lowercase() || character == '_');
    if valid {
        Ok(())
    } else {
        Err(PgError::InvalidVersion {
            version: version.chars().take(MAX_VERSION_BYTES).collect(),
        })
    }
}


/// Versions are valid and strictly ascending, so the order of the list is the order of application.
pub fn check_embedded(migrations: &[Migration]) -> Result<(), PgError> {
    migrations.iter().try_for_each(|migration| check_version(migration.version))?;
    migrations.windows(PAIR).try_for_each(|pair| match pair {
        [earlier, later] if later.version <= earlier.version => Err(PgError::MigrationOrder {
            version: later.version.to_owned(),
            previous: earlier.version.to_owned(),
        }),
        _ => Ok(()),
    })
}


/// The migrations still to apply, in order. An applied one with another digest, unknown to this build, or older than an applied one is refused.
pub fn plan_migrations<'a>(applied: &[AppliedMigration], embedded: &'a [Migration]) -> Result<Vec<&'a Migration>, PgError> {
    check_embedded(embedded)?;
    applied.iter().try_for_each(|done| {
        let known = embedded.iter().find(|migration| migration.version == done.version);
        match known {
            None => Err(PgError::UnknownApplied {
                version: done.version.clone(),
            }),
            Some(migration) if digest_of(migration.sql) != done.digest => Err(PgError::DigestMismatch {
                version: done.version.clone(),
            }),
            Some(_) => Ok(()),
        }
    })?;
    let latest = applied.iter().map(|done| done.version.as_str()).max();
    let pending: Vec<&Migration> = embedded
        .iter()
        .filter(|migration| !applied.iter().any(|done| done.version == migration.version))
        .collect();
    pending.iter().try_for_each(|migration| match latest {
        Some(newest) if migration.version < newest => Err(PgError::OutOfOrder {
            version: migration.version.to_owned(),
        }),
        _ => Ok(()),
    })?;
    Ok(pending)
}


/// Creates the record table under the same advisory lock the migrations take, so concurrent starters cannot race on it.
pub fn bootstrap_script() -> String {
    format!(
        "SELECT pg_catalog.pg_advisory_xact_lock({MIGRATION_LOCK_KEY}); \
         CREATE TABLE IF NOT EXISTS public.schema_migrations (namespace pg_catalog.text NOT NULL, version pg_catalog.text NOT NULL, \
         digest pg_catalog.text NOT NULL, applied_at pg_catalog.timestamptz NOT NULL DEFAULT pg_catalog.now(), \
         PRIMARY KEY (namespace, version))"
    )
}


/// A pending migration may run as long as `MIGRATION_DEADLINE`, or longer when the caller's deadline is longer.
pub fn migration_deadline(caller: Duration) -> Duration {
    caller.max(MIGRATION_DEADLINE)
}


/// Validates the namespace and the version itself; `SET LOCAL lock_timeout` after the lock bounds each table lock wait by `lock_deadline`.
pub fn migration_script(namespace: &str, migration: &Migration, lock_deadline: Duration) -> Result<String, PgError> {
    check_namespace(namespace)?;
    check_version(migration.version)?;
    Ok(format!(
        "SELECT pg_catalog.pg_advisory_xact_lock({MIGRATION_LOCK_KEY}); SET LOCAL lock_timeout = {}; \
         INSERT INTO public.schema_migrations (namespace, version, digest) VALUES ('{namespace}', '{}', '{}'); {}",
        timeout_millis(lock_deadline),
        migration.version,
        digest_of(migration.sql),
        migration.sql
    ))
}


pub async fn read_shape(client: &Client, deadline: Duration) -> Result<TableShape, PgError> {
    let rows = global_query(client, COLUMNS_SQL, deadline).await?;
    let columns = rows.iter().map(|row| column_text(row, 0)).collect::<Result<Vec<String>, PgError>>()?;
    Ok(table_shape(&columns))
}


/// The records of one namespace only: another store's versions are never this build's concern.
pub async fn read_applied(client: &Client, namespace: &str, deadline: Duration) -> Result<Vec<AppliedMigration>, PgError> {
    let rows = global_query(client, &applied_sql(namespace)?, deadline).await?;
    check_row_count(rows.len())?;
    let records = rows
        .iter()
        .map(|row| Ok((column_text(row, 0)?, column_text(row, 1)?, column_text(row, DIGEST_COLUMN)?)))
        .collect::<Result<Vec<(String, String, String)>, PgError>>()?;
    Ok(records
        .into_iter()
        .filter(|(owner, _, _)| owner == namespace)
        .map(|(_, version, digest)| AppliedMigration { version, digest })
        .collect())
}


/// Escapes a signature and keeps `MAX_SIGNATURE_CHARS` characters in all, the last being `CUT_MARKER` when it was longer.
pub fn cut_signature(signature: &str) -> String {
    let escaped: String = signature.escape_debug().collect();
    if escaped.chars().count() > MAX_SIGNATURE_CHARS {
        escaped.chars().take(MAX_SIGNATURE_CHARS - 1).chain(CUT_MARKER.chars()).collect()
    } else {
        escaped
    }
}


/// Refuses every function whose stored `search_path` is not exactly the required text; at most `MAX_NAMED_FUNCTIONS` are named, the count is exact.
pub fn check_search_paths(functions: &[(String, String)]) -> Result<(), PgError> {
    let bad: Vec<String> = functions
        .iter()
        .filter(|(_, setting)| setting != REQUIRED_SEARCH_PATH)
        .map(|(signature, _)| cut_signature(signature))
        .collect();
    if bad.is_empty() {
        Ok(())
    } else {
        Err(PgError::FunctionSearchPath {
            total: bad.len(),
            functions: bad.iter().take(MAX_NAMED_FUNCTIONS).cloned().collect::<Vec<String>>().join(", "),
        })
    }
}


/// Reads the final state from the database, so statement order, overloads and later `CREATE OR REPLACE` cannot hide a function.
pub async fn read_search_paths(client: &Client, deadline: Duration) -> Result<(), PgError> {
    let rows = global_query(client, &functions_sql(), deadline).await?;
    check_row_count(rows.len())?;
    let functions = rows
        .iter()
        .map(|row| Ok((column_text(row, 0)?, column_text(row, 1)?)))
        .collect::<Result<Vec<(String, String)>, PgError>>()?;
    check_search_paths(&functions)
}


pub fn check_isolation(level: Option<&str>) -> Result<(), PgError> {
    match level {
        Some(REQUIRED_ISOLATION) => Ok(()),
        _ => Err(PgError::IsolationLevel),
    }
}


/// Lock-then-count caps of the stores hold only under READ COMMITTED: the connection must run it.
pub async fn read_isolation(client: &Client, deadline: Duration) -> Result<(), PgError> {
    let rows = global_query(client, ISOLATION_SQL, deadline).await?;
    let level = rows.first().map(|row| column_text(row, 0)).transpose()?;
    check_isolation(level.as_deref())
}


pub fn check_row_count(rows: usize) -> Result<usize, PgError> {
    if rows > MAX_APPLIED_ROWS {
        Err(PgError::TooManyRecords { limit: MAX_APPLIED_ROWS })
    } else {
        Ok(rows)
    }
}


pub const UNIQUE_VIOLATION: &str = "23505";


pub fn is_unique_violation(error: &PgError) -> bool {
    matches!(error, PgError::Server { code, .. } if code == UNIQUE_VIOLATION)
}


/// True when `latest` holds a version that neither `before` nor this call's own `done` explains: another caller committed it.
pub fn foreign_progress(before: &[AppliedMigration], latest: &[AppliedMigration], done: &[String]) -> bool {
    latest
        .iter()
        .any(|record| !before.iter().any(|known| known.version == record.version) && !done.contains(&record.version))
}


pub const SQLSTATE_QUERY_CANCELED: &str = "57014";


pub const SQLSTATE_LOCK_NOT_AVAILABLE: &str = "55P03";


/// A server cancel by `statement_timeout` (57014) or `lock_timeout` (55P03) names the migration; any other error is kept as it is.
pub fn name_migration_error(error: PgError, namespace: &str, version: &str, limit_secs: u64, lock_secs: u64) -> PgError {
    match error {
        PgError::Server { code, .. } if code == SQLSTATE_QUERY_CANCELED => PgError::MigrationTimeout {
            namespace: namespace.to_owned(),
            version: version.to_owned(),
            seconds: limit_secs,
        },
        PgError::Server { code, .. } if code == SQLSTATE_LOCK_NOT_AVAILABLE => PgError::MigrationLockWait {
            namespace: namespace.to_owned(),
            version: version.to_owned(),
            seconds: lock_secs,
        },
        other => other,
    }
}


/// One migration under the migration deadline, which the server enforces; the client waits `MIGRATION_CLIENT_MARGIN` longer, only to name the failure.
pub async fn run_migration(client: &Client, namespace: &str, migration: &Migration, deadline: Duration) -> Result<(), PgError> {
    let limit = migration_deadline(deadline);
    let script = timed_script(&migration_script(namespace, migration, deadline)?, limit);
    let version = migration.version;
    let limit_secs = limit.as_secs();
    info!(namespace, version, limit_secs, "applying migration");
    let started = Instant::now();
    timeout(limit + MIGRATION_CLIENT_MARGIN, client.batch_execute(&script))
        .await
        .map_err(|_elapsed| PgError::MigrationTimeout {
            namespace: namespace.to_owned(),
            version: version.to_owned(),
            seconds: limit_secs,
        })?
        .map_err(|error| name_migration_error(reduce(error), namespace, version, limit_secs, deadline.as_secs()))?;
    let elapsed_ms = started.elapsed().as_millis();
    info!(namespace, version, elapsed_ms, "migration applied");
    Ok(())
}


/// Plans against the records read and applies; every version applied is pushed to `done` even when a later one fails.
pub async fn apply_pending(
    client: &Client,
    namespace: &str,
    embedded: &[Migration],
    applied: &[AppliedMigration],
    deadline: Duration,
    done: &mut Vec<String>,
) -> Result<(), PgError> {
    let pending = plan_migrations(applied, embedded)?;
    for migration in pending {
        run_migration(client, namespace, migration, deadline).await?;
        done.push(migration.version.to_owned());
    }
    Ok(())
}


/// Applies the pending migrations in order; a unique violation is retried only on foreign progress, `embedded.len() + 1` attempts at most.
pub async fn migrate(client: &Client, namespace: &str, embedded: &[Migration], deadline: Duration) -> Result<Vec<String>, PgError> {
    check_namespace(namespace)?;
    check_embedded(embedded)?;
    read_isolation(client, deadline).await?;
    info!(namespace, "waiting for the migration lock");
    execute_script(client, &bootstrap_script(), migration_deadline(deadline)).await?;
    check_not_legacy(read_shape(client, deadline).await?)?;
    let mut done = Vec::new();
    let max_attempts = embedded.len() + 1;
    let mut attempts = 1;
    let mut applied = read_applied(client, namespace, deadline).await?;
    let mut outcome = apply_pending(client, namespace, embedded, &applied, deadline, &mut done).await;
    let mut progressed = true;
    while progressed && attempts < MAX_APPLIED_ROWS.min(max_attempts) && outcome.as_ref().is_err_and(is_unique_violation) {
        attempts += 1;
        let latest = read_applied(client, namespace, deadline).await?;
        progressed = foreign_progress(&applied, &latest, &done);
        if progressed {
            outcome = apply_pending(client, namespace, embedded, &latest, deadline, &mut done).await;
        }
        applied = latest;
    }
    outcome?;
    read_search_paths(client, deadline).await?;
    Ok(done)
}
