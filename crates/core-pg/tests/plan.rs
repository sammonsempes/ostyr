use core_pg::error::{sqlstate_class, PgError};
use core_pg::migrate::{
    applied_sql, bootstrap_script, check_namespace, check_not_legacy, check_row_count, check_version, digest_of, foreign_progress,
    migration_deadline, migration_script, plan_migrations, table_shape, AppliedMigration, Migration, TableShape, COLUMNS_SQL, MAX_APPLIED_ROWS,
    MIGRATION_DEADLINE,
};
use core_pg::query::timed_script;
use core_pg::scope::{tenant_of, tenant_scope};
use std::error::Error;
use std::time::Duration;


const SUB_MILLI_MICROS: u64 = 500;


const MAX_NAMESPACE: usize = 32;


const TOO_LONG: usize = 65;


const DEADLINE_SECONDS: u64 = 3;


const DEADLINE_MILLIS: &str = "3000";


const LOCK_DEADLINE: Duration = Duration::from_secs(3);


const ABOVE_CAP_SECS: u64 = 7200;


const FIRST: Migration = Migration {
    version: "0001_init",
    sql: "CREATE TABLE a (tenant text, id text, PRIMARY KEY (tenant, id));",
};


const SECOND: Migration = Migration {
    version: "0002_more",
    sql: "ALTER TABLE a ADD COLUMN note text;",
};


fn applied(migration: &Migration) -> AppliedMigration {
    AppliedMigration {
        version: migration.version.to_owned(),
        digest: digest_of(migration.sql),
    }
}


fn versions(planned: &[&Migration]) -> Vec<&'static str> {
    planned.iter().map(|migration| migration.version).collect()
}


#[test]
fn nothing_applied_plans_everything_in_order() -> Result<(), PgError> {
    let all = [FIRST, SECOND];
    assert_eq!(versions(&plan_migrations(&[], &all)?), ["0001_init", "0002_more"]);
    Ok(())
}


#[test]
fn applied_migrations_are_skipped() -> Result<(), PgError> {
    let all = [FIRST, SECOND];
    assert_eq!(versions(&plan_migrations(&[applied(&FIRST)], &all)?), ["0002_more"]);
    assert!(plan_migrations(&[applied(&FIRST), applied(&SECOND)], &all)?.is_empty());
    Ok(())
}


#[test]
fn a_changed_migration_is_refused() -> Result<(), Box<dyn Error>> {
    let altered = Migration {
        version: "0001_init",
        sql: "DROP TABLE a;",
    };
    let list = [altered, SECOND];
    let result = plan_migrations(&[applied(&FIRST)], &list);
    assert!(matches!(result, Err(PgError::DigestMismatch { version }) if version == "0001_init"));
    Ok(())
}


#[test]
fn unknown_and_out_of_order_migrations_are_refused() -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        plan_migrations(&[applied(&SECOND)], &[FIRST]),
        Err(PgError::UnknownApplied { .. })
    ));
    assert!(matches!(
        plan_migrations(&[applied(&SECOND)], &[FIRST, SECOND]),
        Err(PgError::OutOfOrder { version }) if version == "0001_init"
    ));
    Ok(())
}


#[test]
fn embedded_list_must_be_valid_and_ascending() -> Result<(), Box<dyn Error>> {
    assert!(matches!(plan_migrations(&[], &[SECOND, FIRST]), Err(PgError::MigrationOrder { .. })));
    assert!(matches!(plan_migrations(&[], &[FIRST, FIRST]), Err(PgError::MigrationOrder { .. })));
    let bad = Migration {
        version: "0003 x'; DROP",
        sql: "",
    };
    assert!(matches!(plan_migrations(&[], &[bad]), Err(PgError::InvalidVersion { .. })));
    assert!(check_version("").is_err());
    assert!(check_version(&"a".repeat(TOO_LONG)).is_err());
    assert!(check_version("0001_a").is_ok());
    Ok(())
}


#[test]
fn scripts_take_the_lock_and_record_before_the_sql() -> Result<(), Box<dyn Error>> {
    let script = migration_script("store", &FIRST, LOCK_DEADLINE)?;
    let lock = script.find("pg_advisory_xact_lock").unwrap_or(usize::MAX);
    let record = script.find("INSERT INTO public.schema_migrations").unwrap_or(usize::MAX);
    let sql = script.find("CREATE TABLE a").unwrap_or(usize::MAX);
    assert!(lock < record && record < sql, "{script}");
    assert!(script.contains(&digest_of(FIRST.sql)) && script.contains("('store', '0001_init'"));
    assert!(!script.contains("BEGIN") && !script.contains("COMMIT"));
    let bootstrap = bootstrap_script();
    assert!(bootstrap.find("pg_advisory_xact_lock") < bootstrap.find("CREATE TABLE IF NOT EXISTS public.schema_migrations"));
    Ok(())
}


#[test]
fn statement_timeout_is_prefixed_in_milliseconds() -> Result<(), Box<dyn Error>> {
    let script = timed_script("SELECT 1", Duration::from_secs(DEADLINE_SECONDS));
    assert_eq!(script, format!("SET statement_timeout = {DEADLINE_MILLIS}; SELECT 1"));
    Ok(())
}


#[test]
fn statement_timeout_is_never_zero() -> Result<(), Box<dyn Error>> {
    assert_eq!(timed_script("X", Duration::ZERO), "SET statement_timeout = 1; X");
    assert_eq!(timed_script("X", Duration::from_micros(SUB_MILLI_MICROS)), "SET statement_timeout = 1; X");
    assert_eq!(timed_script("X", Duration::from_millis(1)), "SET statement_timeout = 1; X");
    assert!(timed_script("X", Duration::from_secs(u64::MAX)).starts_with("SET statement_timeout = 18446744073709551615000;"));
    Ok(())
}


#[test]
fn sqlstate_codes_reduce_to_fixed_classes() -> Result<(), Box<dyn Error>> {
    let expected = [
        ("08006", "connection exception"),
        ("23505", "integrity constraint violation"),
        ("28P01", "invalid authorization"),
        ("40001", "transaction rollback"),
        ("42601", "syntax error or access rule violation"),
        ("53300", "insufficient resources"),
        ("57014", "operator intervention"),
        ("XX000", "internal error"),
        ("P0001", "other"),
        ("", "other"),
    ];
    expected.iter().for_each(|(code, class)| assert_eq!(sqlstate_class(code), *class));
    Ok(())
}


#[test]
fn tenant_scope_accepts_identifiers_only() -> Result<(), PgError> {
    assert_eq!(tenant_of(&tenant_scope("acme-1.eu_west")?), "acme-1.eu_west");
    ["", "-a", "a b", "a'b", "é", &"a".repeat(TOO_LONG)]
        .iter()
        .for_each(|bad| assert!(matches!(tenant_scope(bad), Err(PgError::InvalidTenant)), "{bad}"));
    Ok(())
}


#[test]
fn plan_error_messages_name_versions_only() -> Result<(), Box<dyn Error>> {
    let message = plan_migrations(
        &[applied(&FIRST)],
        &[Migration {
            version: "0001_init",
            sql: "x",
        }],
    )
    .err()
    .ok_or("accepted")?
    .to_string();
    assert!(message.contains("0001_init") && !message.contains("CREATE"), "{message}");
    Ok(())
}


#[test]
fn namespaces_are_lowercase_identifiers() -> Result<(), Box<dyn Error>> {
    ["oncall", "a", "cmdb_2", &"a".repeat(MAX_NAMESPACE)]
        .iter()
        .try_for_each(|good| check_namespace(good))?;
    ["", "1a", "_a", "A", "a-b", "a'b", "é", &"a".repeat(MAX_NAMESPACE + 1)]
        .iter()
        .for_each(|bad| assert!(matches!(check_namespace(bad), Err(PgError::InvalidNamespace { .. })), "{bad}"));
    Ok(())
}


#[test]
fn table_shapes_are_told_apart() -> Result<(), Box<dyn Error>> {
    let legacy = ["version".to_owned(), "digest".to_owned()];
    let current = ["namespace".to_owned(), "version".to_owned()];
    assert_eq!(table_shape(&[]), TableShape::Absent);
    assert_eq!(table_shape(&legacy), TableShape::Legacy);
    assert_eq!(table_shape(&current), TableShape::Namespaced);
    assert!(matches!(check_not_legacy(TableShape::Legacy), Err(PgError::LegacyRecords)));
    check_not_legacy(TableShape::Absent)?;
    check_not_legacy(TableShape::Namespaced)?;
    Ok(())
}


const HOSTILE: &str = "x' || current_user || '";


#[test]
fn the_applied_query_names_the_namespace_and_caps_the_rows() -> Result<(), Box<dyn Error>> {
    assert!(applied_sql("oncall")?.contains("WHERE namespace OPERATOR(pg_catalog.=) 'oncall'"));
    assert!(check_row_count(MAX_APPLIED_ROWS).is_ok() && check_row_count(MAX_APPLIED_ROWS + 1).is_err());
    Ok(())
}


#[test]
fn every_sql_builder_refuses_a_hostile_namespace_or_version_itself() -> Result<(), Box<dyn Error>> {
    assert!(matches!(applied_sql(HOSTILE), Err(PgError::InvalidNamespace { .. })));
    assert!(matches!(
        migration_script(HOSTILE, &FIRST, LOCK_DEADLINE),
        Err(PgError::InvalidNamespace { .. })
    ));
    let hostile_version = Migration {
        version: "a'; DROP TABLE x; --",
        sql: "SELECT 1;",
    };
    assert!(matches!(
        migration_script("store", &hostile_version, LOCK_DEADLINE),
        Err(PgError::InvalidVersion { .. })
    ));
    Ok(())
}


const EXPECTED_BOOTSTRAP: &str = "SELECT pg_catalog.pg_advisory_xact_lock(7021103100); \
    CREATE TABLE IF NOT EXISTS public.schema_migrations (namespace pg_catalog.text NOT NULL, version pg_catalog.text NOT NULL, \
    digest pg_catalog.text NOT NULL, applied_at pg_catalog.timestamptz NOT NULL DEFAULT pg_catalog.now(), PRIMARY KEY (namespace, version))";


const EXPECTED_APPLIED: &str = "SELECT namespace, version, digest FROM public.schema_migrations WHERE namespace OPERATOR(pg_catalog.=) 'store' \
    ORDER BY version LIMIT 10001";


const EXPECTED_COLUMNS: &str =
    "SELECT column_name::pg_catalog.text FROM information_schema.columns WHERE table_schema OPERATOR(pg_catalog.=) 'public' \
     AND table_name OPERATOR(pg_catalog.=) 'schema_migrations'";


#[test]
fn the_record_statements_are_pinned_as_exact_qualified_text() -> Result<(), Box<dyn Error>> {
    assert_eq!(bootstrap_script(), EXPECTED_BOOTSTRAP);
    assert_eq!(applied_sql("store")?, EXPECTED_APPLIED);
    assert_eq!(COLUMNS_SQL, EXPECTED_COLUMNS);
    let expected_script = format!(
        "SELECT pg_catalog.pg_advisory_xact_lock(7021103100); SET LOCAL lock_timeout = 3000; INSERT INTO public.schema_migrations (namespace, version, digest) \
         VALUES ('store', '0001_init', '{}'); {}",
        digest_of(FIRST.sql),
        FIRST.sql
    );
    assert_eq!(migration_script("store", &FIRST, LOCK_DEADLINE)?, expected_script);
    Ok(())
}


#[test]
fn a_migration_lock_wait_is_never_unbounded() -> Result<(), Box<dyn Error>> {
    let script = migration_script("store", &FIRST, Duration::ZERO)?;
    assert!(script.contains("SET LOCAL lock_timeout = 1;"), "{script}");
    let lock = script.find("pg_advisory_xact_lock").unwrap_or(usize::MAX);
    let timeout = script.find("SET LOCAL lock_timeout").unwrap_or(usize::MAX);
    assert!(lock < timeout);
    Ok(())
}


#[test]
fn the_migration_deadline_is_the_larger_of_the_caller_and_the_constant() -> Result<(), Box<dyn Error>> {
    assert_eq!(migration_deadline(Duration::from_secs(DEADLINE_SECONDS)), MIGRATION_DEADLINE);
    assert_eq!(MIGRATION_DEADLINE, Duration::from_secs(core_pg::settings::MAX_DEADLINE_SECS));
    let above = Duration::from_secs(ABOVE_CAP_SECS);
    assert_eq!(migration_deadline(above), above);
    Ok(())
}


fn record(version: &str) -> AppliedMigration {
    AppliedMigration {
        version: version.to_owned(),
        digest: String::new(),
    }
}


#[test]
fn only_a_record_nobody_here_explains_is_foreign_progress() -> Result<(), Box<dyn Error>> {
    let before = vec![record("0001")];
    let done = vec!["0002".to_owned()];
    assert!(!foreign_progress(&before, &[record("0001"), record("0002")], &done));
    assert!(!foreign_progress(&before, &before, &[]));
    assert!(foreign_progress(&before, &[record("0001"), record("0003")], &done));
    Ok(())
}
