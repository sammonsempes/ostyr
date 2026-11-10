use crate::drain;
use crate::fake::Reply;
use crate::query::client_with;
use crate::types::Handler;
use core_pg::error::PgError;
use core_pg::migrate::{digest_of, migrate, read_applied, Migration, MAX_APPLIED_ROWS};
use std::error::Error;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;


const DEADLINE: Duration = Duration::from_secs(30);


const NAMESPACE: &str = "store";


const ONE_MIGRATION_ATTEMPTS: usize = 2;


const SCRIPTS: usize = 3;


const SECOND_SCRIPT: usize = 2;


const FIRST: Migration = Migration {
    version: "0001_init",
    sql: "CREATE TABLE a (tenant text, id text, PRIMARY KEY (tenant, id));",
};


const THIRD: Migration = Migration {
    version: "0003_third",
    sql: "SELECT 3;",
};


const FOURTH: Migration = Migration {
    version: "0004_fourth",
    sql: "SELECT 4;",
};


const SECOND: Migration = Migration {
    version: "0002_more",
    sql: "ALTER TABLE a ADD COLUMN note text;",
};


pub fn applied_handler(applied: Vec<Vec<String>>) -> Handler {
    shaped_handler(applied, vec!["namespace", "version", "digest"])
}


fn shaped_handler(applied: Vec<Vec<String>>, columns: Vec<&'static str>) -> Handler {
    Arc::new(move |sql| {
        if sql.contains("information_schema.columns") {
            Reply::Rows(columns.iter().map(|column| vec![(*column).to_owned()]).collect())
        } else if sql.contains("FROM schema_migrations") {
            Reply::Rows(applied.clone())
        } else if sql.contains("FAILING") {
            Reply::Error("23505")
        } else {
            Reply::Done
        }
    })
}


fn row_of(migration: &Migration) -> Vec<String> {
    owned_row(NAMESPACE, migration)
}


fn owned_row(namespace: &str, migration: &Migration) -> Vec<String> {
    vec![namespace.to_owned(), migration.version.to_owned(), digest_of(migration.sql)]
}


#[tokio::test]
async fn a_fresh_database_gets_every_migration_in_order_under_the_lock() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(applied_handler(Vec::new())).await?;
    let done = migrate(&client, NAMESPACE, &[FIRST, SECOND], DEADLINE).await?;
    assert_eq!(done, ["0001_init", "0002_more"]);
    let statements = drain(&mut fake.statements);
    let scripts: Vec<&String> = statements.iter().filter(|sql| sql.contains("pg_advisory_xact_lock")).collect();
    assert_eq!(scripts.len(), SCRIPTS, "{statements:?}");
    assert!(scripts
        .get(1)
        .is_some_and(|sql| sql.contains("CREATE TABLE a") && sql.contains("'0001_init'")));
    assert!(scripts.get(SECOND_SCRIPT).is_some_and(|sql| sql.contains("ADD COLUMN note")));
    Ok(())
}


#[tokio::test]
async fn a_second_run_applies_nothing() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(applied_handler(vec![row_of(&FIRST), row_of(&SECOND)])).await?;
    assert!(migrate(&client, NAMESPACE, &[FIRST, SECOND], DEADLINE).await?.is_empty());
    let statements = drain(&mut fake.statements);
    assert!(
        !statements.iter().any(|sql| sql.contains("INSERT INTO schema_migrations")),
        "{statements:?}"
    );
    Ok(())
}


#[tokio::test]
async fn an_altered_migration_is_refused_before_anything_runs() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(applied_handler(vec![row_of(&FIRST)])).await?;
    let altered = Migration {
        version: "0001_init",
        sql: "DROP TABLE a;",
    };
    let result = migrate(&client, NAMESPACE, &[altered, SECOND], DEADLINE).await;
    assert!(matches!(result, Err(PgError::DigestMismatch { .. })));
    assert!(!drain(&mut fake.statements)
        .iter()
        .any(|sql| sql.contains("INSERT INTO schema_migrations")));
    Ok(())
}


#[tokio::test]
async fn an_invalid_list_is_refused_without_touching_the_database() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(applied_handler(Vec::new())).await?;
    let result = migrate(&client, NAMESPACE, &[SECOND, FIRST], DEADLINE).await;
    assert!(matches!(result, Err(PgError::MigrationOrder { .. })));
    assert!(drain(&mut fake.statements).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_failing_migration_is_reduced_to_its_sqlstate() -> Result<(), Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(applied_handler(Vec::new())).await?;
    let failing = Migration {
        version: "0003_bad",
        sql: "SELECT FAILING;",
    };
    let result = migrate(&client, NAMESPACE, &[failing], DEADLINE).await;
    assert!(matches!(result, Err(PgError::Server { code, .. }) if code == "23505"));
    Ok(())
}


#[tokio::test]
async fn a_unique_violation_forever_ends_after_the_attempt_cap() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(applied_handler(Vec::new())).await?;
    let failing = Migration {
        version: "0003_bad",
        sql: "SELECT FAILING;",
    };
    let result = migrate(&client, NAMESPACE, &[failing], DEADLINE).await;
    assert!(matches!(result, Err(PgError::Server { code, .. }) if code == "23505"));
    let failures = drain(&mut fake.statements).iter().filter(|sql| sql.contains("FAILING")).count();
    assert_eq!(failures, ONE_MIGRATION_ATTEMPTS);
    Ok(())
}


#[tokio::test]
async fn another_server_error_is_returned_without_a_retry() -> Result<(), Box<dyn Error>> {
    let handler: Handler = Arc::new(|sql| {
        if sql.contains("information_schema.columns") {
            Reply::Rows(vec![vec!["namespace".to_owned()]])
        } else if sql.contains("FROM schema_migrations") {
            Reply::Rows(Vec::new())
        } else if sql.contains("'0001_init'") {
            Reply::Error("42601")
        } else {
            Reply::Done
        }
    });
    let (client, mut fake, _dir) = client_with(handler).await?;
    let result = migrate(&client, NAMESPACE, &[FIRST], DEADLINE).await;
    assert!(matches!(result, Err(PgError::Server { code, .. }) if code == "42601"));
    let attempts = drain(&mut fake.statements).iter().filter(|sql| sql.contains("'0001_init'")).count();
    assert_eq!(attempts, 1);
    Ok(())
}


fn racing_handler(failing_marker: &'static str, after_race: Vec<Vec<String>>) -> Handler {
    let reads = Arc::new(AtomicUsize::new(0));
    Arc::new(move |sql| {
        if sql.contains("information_schema.columns") {
            Reply::Rows(vec![vec!["namespace".to_owned()]])
        } else if sql.contains("FROM schema_migrations") {
            match reads.fetch_add(1, Ordering::SeqCst) {
                0 => Reply::Rows(Vec::new()),
                _ => Reply::Rows(after_race.clone()),
            }
        } else if sql.contains(failing_marker) {
            Reply::Error("23505")
        } else {
            Reply::Done
        }
    })
}


#[tokio::test]
async fn a_concurrent_caller_that_applied_first_is_skipped_on_the_retry() -> Result<(), Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(racing_handler("'0001_init'", vec![row_of(&FIRST)])).await?;
    assert_eq!(migrate(&client, NAMESPACE, &[FIRST, SECOND], DEADLINE).await?, ["0002_more"]);
    Ok(())
}


#[tokio::test]
async fn a_concurrent_caller_that_did_everything_leaves_an_empty_result() -> Result<(), Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(racing_handler("'0001_init'", vec![row_of(&FIRST)])).await?;
    assert!(migrate(&client, NAMESPACE, &[FIRST], DEADLINE).await?.is_empty());
    Ok(())
}


fn losing_every_insert_handler(all: Vec<Migration>) -> Handler {
    let reads = Arc::new(AtomicUsize::new(0));
    Arc::new(move |sql| {
        if sql.contains("information_schema.columns") {
            Reply::Rows(vec![vec!["namespace".to_owned()]])
        } else if sql.contains("FROM schema_migrations") {
            let winners = reads.fetch_add(1, Ordering::SeqCst);
            Reply::Rows(all.iter().take(winners).map(row_of).collect())
        } else if sql.contains("INSERT INTO schema_migrations") {
            Reply::Error("23505")
        } else {
            Reply::Done
        }
    })
}


#[tokio::test]
async fn every_insert_losing_to_another_caller_still_ends_within_the_bound() -> Result<(), Box<dyn Error>> {
    let all = vec![FIRST, SECOND, THIRD, FOURTH];
    let (client, mut fake, _dir) = client_with(losing_every_insert_handler(all.clone())).await?;
    assert!(migrate(&client, NAMESPACE, &all, DEADLINE).await?.is_empty());
    let inserts = drain(&mut fake.statements)
        .iter()
        .filter(|sql| sql.contains("INSERT INTO schema_migrations"))
        .count();
    assert_eq!(inserts, all.len());
    Ok(())
}


#[tokio::test]
async fn versions_applied_before_a_unique_violation_stay_in_the_result() -> Result<(), Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(racing_handler("'0002_more'", vec![row_of(&FIRST), row_of(&SECOND)])).await?;
    assert_eq!(migrate(&client, NAMESPACE, &[FIRST, SECOND], DEADLINE).await?, ["0001_init"]);
    Ok(())
}


#[tokio::test]
async fn malformed_record_rows_are_errors() -> Result<(), Box<dyn Error>> {
    let (one_column, _fake, _dir) = client_with(applied_handler(vec![vec!["store".to_owned(), "0001_init".to_owned()]])).await?;
    assert!(matches!(read_applied(&one_column, NAMESPACE, DEADLINE).await, Err(PgError::Client(_))));
    let ints: Handler = Arc::new(|_sql| Reply::IntRows(vec![1]));
    let (integers, _other, _other_dir) = client_with(ints).await?;
    assert!(matches!(read_applied(&integers, NAMESPACE, DEADLINE).await, Err(PgError::Client(_))));
    Ok(())
}


#[tokio::test]
async fn another_namespace_is_ignored_and_its_versions_never_refused() -> Result<(), Box<dyn Error>> {
    let foreign = Migration {
        version: "9999_foreign",
        sql: "SELECT 1;",
    };
    let rows = vec![owned_row("other", &foreign), owned_row("other", &FIRST), row_of(&FIRST)];
    let (client, mut fake, _dir) = client_with(applied_handler(rows)).await?;
    assert_eq!(migrate(&client, NAMESPACE, &[FIRST, SECOND], DEADLINE).await?, ["0002_more"]);
    let statements = drain(&mut fake.statements);
    assert!(statements.iter().any(|sql| sql.contains("('store', '0002_more'")), "{statements:?}");
    Ok(())
}


#[tokio::test]
async fn an_unknown_version_inside_the_namespace_is_refused() -> Result<(), Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(applied_handler(vec![row_of(&SECOND)])).await?;
    let result = migrate(&client, NAMESPACE, &[FIRST], DEADLINE).await;
    assert!(matches!(result, Err(PgError::UnknownApplied { .. })));
    Ok(())
}


#[tokio::test]
async fn two_namespaces_migrate_in_either_order() -> Result<(), Box<dyn Error>> {
    let other = Migration {
        version: "0001_init",
        sql: "CREATE TABLE b (tenant text);",
    };
    let (client, _fake, _dir) = client_with(applied_handler(vec![owned_row("beta", &other)])).await?;
    assert_eq!(migrate(&client, "alpha", &[FIRST], DEADLINE).await?, ["0001_init"]);
    let (second, _second_fake, _second_dir) = client_with(applied_handler(vec![owned_row("alpha", &FIRST)])).await?;
    assert_eq!(migrate(&second, "beta", &[other], DEADLINE).await?, ["0001_init"]);
    Ok(())
}


#[tokio::test]
async fn an_invalid_namespace_is_refused_without_touching_the_database() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(applied_handler(Vec::new())).await?;
    assert!(matches!(
        migrate(&client, "bad'; DROP", &[FIRST], DEADLINE).await,
        Err(PgError::InvalidNamespace { .. })
    ));
    assert!(matches!(
        read_applied(&client, "x' || current_user || '", DEADLINE).await,
        Err(PgError::InvalidNamespace { .. })
    ));
    assert!(drain(&mut fake.statements).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_legacy_table_is_refused_and_left_unchanged() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(shaped_handler(Vec::new(), vec!["version", "digest"])).await?;
    assert!(matches!(
        migrate(&client, NAMESPACE, &[FIRST], DEADLINE).await,
        Err(PgError::LegacyRecords)
    ));
    assert!(!drain(&mut fake.statements)
        .iter()
        .any(|sql| sql.contains("INSERT INTO schema_migrations")));
    Ok(())
}


#[tokio::test]
async fn more_records_than_the_cap_are_refused_not_truncated() -> Result<(), Box<dyn Error>> {
    let rows = vec![row_of(&FIRST); MAX_APPLIED_ROWS + 1];
    let (client, mut fake, _dir) = client_with(applied_handler(rows)).await?;
    assert!(matches!(
        read_applied(&client, NAMESPACE, DEADLINE).await,
        Err(PgError::TooManyRecords { .. })
    ));
    assert!(drain(&mut fake.statements)
        .iter()
        .any(|sql| sql.contains("WHERE namespace = 'store'") && sql.contains("LIMIT 10001")));
    Ok(())
}
