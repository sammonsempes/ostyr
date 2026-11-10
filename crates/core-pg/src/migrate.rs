use crate::error::PgError;
use crate::query::{column_text, execute_script, global_query};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio_postgres::Client;


pub const MIGRATION_LOCK_KEY: i64 = 7_021_103_100;


pub const PAIR: usize = 2;


pub const MAX_VERSION_BYTES: usize = 64;


pub const MAX_APPLIED_ROWS: usize = 10_000;


/// Validates the namespace itself; one row past the cap is read so that an overflow is refused, never truncated.
pub fn applied_sql(namespace: &str) -> Result<String, PgError> {
    check_namespace(namespace)?;
    Ok(format!(
        "SELECT namespace, version, digest FROM schema_migrations WHERE namespace = '{namespace}' ORDER BY version LIMIT {}",
        MAX_APPLIED_ROWS + 1
    ))
}


pub const COLUMNS_SQL: &str =
    "SELECT column_name::text FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'schema_migrations'";


pub const DIGEST_COLUMN: usize = 2;


pub const MAX_NAMESPACE_BYTES: usize = 32;


pub const NAMESPACE_COLUMN: &str = "namespace";


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
        "SELECT pg_advisory_xact_lock({MIGRATION_LOCK_KEY}); \
         CREATE TABLE IF NOT EXISTS schema_migrations \
         (namespace text NOT NULL, version text NOT NULL, digest text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now(), \
         PRIMARY KEY (namespace, version))"
    )
}


/// Validates the namespace and the version itself. One simple-query message is one implicit transaction, so a dropped future cannot leave one open.
pub fn migration_script(namespace: &str, migration: &Migration) -> Result<String, PgError> {
    check_namespace(namespace)?;
    check_version(migration.version)?;
    Ok(format!(
        "SELECT pg_advisory_xact_lock({MIGRATION_LOCK_KEY}); \
         INSERT INTO schema_migrations (namespace, version, digest) VALUES ('{namespace}', '{}', '{}'); {}",
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


pub fn check_row_count(rows: usize) -> Result<usize, PgError> {
    if rows > MAX_APPLIED_ROWS {
        Err(PgError::TooManyRecords { limit: MAX_APPLIED_ROWS })
    } else {
        Ok(rows)
    }
}


pub const MAX_MIGRATE_ATTEMPTS: usize = 3;


pub const UNIQUE_VIOLATION: &str = "23505";


pub fn is_unique_violation(error: &PgError) -> bool {
    matches!(error, PgError::Server { code, .. } if code == UNIQUE_VIOLATION)
}


/// Reads the records, plans and applies; every version applied is pushed to `done` even when a later one fails.
pub async fn apply_pending(
    client: &Client,
    namespace: &str,
    embedded: &[Migration],
    deadline: Duration,
    done: &mut Vec<String>,
) -> Result<(), PgError> {
    let applied = read_applied(client, namespace, deadline).await?;
    let pending = plan_migrations(&applied, embedded)?;
    for migration in pending {
        execute_script(client, &migration_script(namespace, migration)?, deadline).await?;
        done.push(migration.version.to_owned());
    }
    Ok(())
}


/// Applies the pending migrations in order; a unique violation (a concurrent caller won) re-reads and re-plans, `MAX_MIGRATE_ATTEMPTS` times at most.
pub async fn migrate(client: &Client, namespace: &str, embedded: &[Migration], deadline: Duration) -> Result<Vec<String>, PgError> {
    check_namespace(namespace)?;
    check_embedded(embedded)?;
    execute_script(client, &bootstrap_script(), deadline).await?;
    check_not_legacy(read_shape(client, deadline).await?)?;
    let mut done = Vec::new();
    let mut attempts = 1;
    let mut outcome = apply_pending(client, namespace, embedded, deadline, &mut done).await;
    while attempts < MAX_MIGRATE_ATTEMPTS && outcome.as_ref().is_err_and(is_unique_violation) {
        attempts += 1;
        outcome = apply_pending(client, namespace, embedded, deadline, &mut done).await;
    }
    outcome?;
    Ok(done)
}
