use crate::drain;
use crate::fake::Reply;
use crate::query::client_with;
use crate::types::Handler;
use core_pg::error::PgError;
use core_pg::migrate::{adopt_legacy, digest_of, migrate, read_applied, Migration};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;


const DEADLINE: Duration = Duration::from_secs(30);


const NAMESPACE: &str = "store";


const SCRIPTS: usize = 3;


const SECOND_SCRIPT: usize = 2;


const FIRST: Migration = Migration {
    version: "0001_init",
    sql: "CREATE TABLE a (tenant text, id text, PRIMARY KEY (tenant, id));",
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
    assert!(matches!(adopt_legacy(&client, "", DEADLINE).await, Err(PgError::InvalidNamespace { .. })));
    assert!(drain(&mut fake.statements).is_empty());
    Ok(())
}


#[tokio::test]
async fn a_legacy_table_is_refused_until_adopted() -> Result<(), Box<dyn Error>> {
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
async fn adoption_rewrites_a_legacy_table_once_and_is_a_no_op_otherwise() -> Result<(), Box<dyn Error>> {
    let (legacy, mut fake, _dir) = client_with(shaped_handler(Vec::new(), vec!["version", "digest"])).await?;
    assert!(adopt_legacy(&legacy, NAMESPACE, DEADLINE).await?);
    let statements = drain(&mut fake.statements);
    assert!(statements.iter().any(|sql| sql.contains("DEFAULT 'store'")), "{statements:?}");
    let (current, mut current_fake, _current_dir) = client_with(applied_handler(Vec::new())).await?;
    assert!(!adopt_legacy(&current, NAMESPACE, DEADLINE).await?);
    assert!(!drain(&mut current_fake.statements).iter().any(|sql| sql.contains("ALTER TABLE")));
    Ok(())
}
