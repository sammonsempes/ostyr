use crate::error::PgError;
use crate::query::{column_text, execute_script, global_query};
use sha2::{Digest, Sha256};
use std::time::Duration;
use tokio_postgres::Client;


pub const MIGRATION_LOCK_KEY: i64 = 7_021_103_100;


pub const PAIR: usize = 2;


pub const MAX_VERSION_BYTES: usize = 64;


pub const APPLIED_SQL: &str = "SELECT version, digest FROM schema_migrations ORDER BY version";


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
         (version text PRIMARY KEY, digest text NOT NULL, applied_at timestamptz NOT NULL DEFAULT now())"
    )
}


/// One simple-query message is one implicit transaction: lock, record (a duplicate version fails), then the SQL; any failure rolls all back.
pub fn migration_script(migration: &Migration) -> String {
    format!(
        "SELECT pg_advisory_xact_lock({MIGRATION_LOCK_KEY}); \
         INSERT INTO schema_migrations (version, digest) VALUES ('{}', '{}'); {}",
        migration.version,
        digest_of(migration.sql),
        migration.sql
    )
}


pub async fn read_applied(client: &Client, deadline: Duration) -> Result<Vec<AppliedMigration>, PgError> {
    let rows = global_query(client, APPLIED_SQL, deadline).await?;
    rows.iter()
        .map(|row| {
            Ok(AppliedMigration {
                version: column_text(row, 0)?,
                digest: column_text(row, 1)?,
            })
        })
        .collect()
}


/// Applies the pending migrations in order and returns their versions; a second run applies nothing.
pub async fn migrate(client: &Client, embedded: &[Migration], deadline: Duration) -> Result<Vec<String>, PgError> {
    check_embedded(embedded)?;
    execute_script(client, &bootstrap_script(), deadline).await?;
    let applied = read_applied(client, deadline).await?;
    let pending = plan_migrations(&applied, embedded)?;
    for migration in &pending {
        execute_script(client, &migration_script(migration), deadline).await?;
    }
    Ok(pending.iter().map(|migration| migration.version.to_owned()).collect())
}
