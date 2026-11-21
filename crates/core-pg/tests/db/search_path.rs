use crate::drain;
use crate::fake::Reply;
use crate::query::client_with;
use crate::types::Handler;
use core_pg::error::PgError;
use core_pg::migrate::{check_search_paths, digest_of, functions_sql, migrate, read_search_paths, Migration, MAX_APPLIED_ROWS};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;


const DEADLINE: Duration = Duration::from_secs(30);


const NAMESPACE: &str = "store";


const GOOD: &str = "search_path=pg_catalog, public, pg_temp";


const MANY: usize = 25;


const NAMED: usize = 20;


const FIRST: Migration = Migration {
    version: "0001_init",
    sql: "SELECT 1;",
};


fn function(signature: &str, setting: &str) -> Vec<String> {
    vec![signature.to_owned(), setting.to_owned()]
}


fn handler(applied: bool, functions: Reply) -> Handler {
    Arc::new(move |sql| {
        if sql.contains("information_schema.columns") {
            Reply::Rows(vec![vec!["namespace".to_owned()]])
        } else if sql.contains("FROM schema_migrations") {
            Reply::Rows(if applied {
                vec![vec![NAMESPACE.to_owned(), FIRST.version.to_owned(), digest_of(FIRST.sql)]]
            } else {
                Vec::new()
            })
        } else if sql.contains("FROM pg_proc") {
            functions.clone()
        } else {
            Reply::Done
        }
    })
}


async fn run(applied: bool, functions: Reply) -> Result<Result<Vec<String>, PgError>, Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(handler(applied, functions)).await?;
    Ok(migrate(&client, NAMESPACE, &[FIRST], DEADLINE).await)
}


#[tokio::test]
async fn no_function_and_a_compliant_function_start() -> Result<(), Box<dyn Error>> {
    assert_eq!(run(false, Reply::Rows(Vec::new())).await??, ["0001_init"]);
    assert_eq!(run(false, Reply::Rows(vec![function("f(text)", GOOD)])).await??, ["0001_init"]);
    Ok(())
}


#[tokio::test]
async fn a_function_without_pg_temp_is_refused_named_by_signature() -> Result<(), Box<dyn Error>> {
    let result = run(false, Reply::Rows(vec![function("f(text)", "search_path=pg_catalog, public")])).await?;
    let error = result.err().ok_or("expected a refusal")?;
    assert!(matches!(&error, PgError::FunctionSearchPath { total: 1, functions } if functions == "f(text)"));
    assert!(error.to_string().contains("any module"), "{error}");
    Ok(())
}


#[tokio::test]
async fn the_check_runs_when_no_migration_is_pending() -> Result<(), Box<dyn Error>> {
    let result = run(true, Reply::Rows(vec![function("g(int4)", "")])).await?;
    assert!(matches!(result, Err(PgError::FunctionSearchPath { total: 1, .. })));
    assert!(run(true, Reply::Rows(vec![function("g(int4)", GOOD)])).await??.is_empty());
    Ok(())
}


#[tokio::test]
async fn only_the_canonical_text_passes() -> Result<(), Box<dyn Error>> {
    let forms = [
        "search_path=pg_catalog, public, pg_temp, extra",
        "search_path=pg_catalog, pg_temp, public",
        "search_path=pg_catalog, public, \"pg_temp\"",
        "search_path=pg_catalog,  public, pg_temp",
        "search_path=public, pg_temp",
        "enable_sort=off",
        "",
    ];
    forms.iter().for_each(|form| {
        let result = check_search_paths(&[("f()".to_owned(), (*form).to_owned())]);
        assert!(matches!(result, Err(PgError::FunctionSearchPath { .. })), "{form}");
    });
    assert!(check_search_paths(&[("f()".to_owned(), GOOD.to_owned())]).is_ok());
    Ok(())
}


#[tokio::test]
async fn twenty_five_bad_functions_name_twenty_and_count_all() -> Result<(), Box<dyn Error>> {
    let rows: Vec<Vec<String>> = (0..MANY).map(|index| function(&format!("f{index:02}()"), "")).collect();
    let result = run(false, Reply::Rows(rows)).await?;
    assert!(matches!(&result, Err(PgError::FunctionSearchPath { total, functions })
        if *total == MANY && functions.split(", ").count() == NAMED && functions.contains("f19()") && !functions.contains("f20()")));
    Ok(())
}


#[tokio::test]
async fn a_hostile_signature_is_escaped_and_cut() -> Result<(), Box<dyn Error>> {
    let hostile = format!("\u{1b}[31m{}", "x".repeat(MAX_APPLIED_ROWS));
    let result = check_search_paths(&[(hostile, String::new())]);
    assert!(matches!(&result, Err(PgError::FunctionSearchPath { functions, .. })
        if !functions.contains('\u{1b}') && functions.chars().count() < MAX_APPLIED_ROWS));
    Ok(())
}


#[tokio::test]
async fn a_malformed_row_and_too_many_rows_are_errors() -> Result<(), Box<dyn Error>> {
    let (client, _fake, _dir) = client_with(handler(true, Reply::IntRows(vec![1]))).await?;
    assert!(read_search_paths(&client, DEADLINE).await.is_err());
    let rows = vec![function("f()", GOOD); MAX_APPLIED_ROWS + 1];
    let (second, _other, _second_dir) = client_with(handler(true, Reply::Rows(rows))).await?;
    assert!(matches!(read_search_paths(&second, DEADLINE).await, Err(PgError::TooManyRecords { .. })));
    Ok(())
}


#[tokio::test]
async fn the_query_reads_public_functions_outside_extensions_in_the_same_connection() -> Result<(), Box<dyn Error>> {
    let (client, mut fake, _dir) = client_with(handler(true, Reply::Rows(Vec::new()))).await?;
    assert!(migrate(&client, NAMESPACE, &[FIRST], DEADLINE).await?.is_empty());
    let sql = functions_sql();
    assert!(drain(&mut fake.statements).iter().any(|statement| statement == &sql));
    assert!(sql.contains("'public'::regnamespace") && sql.contains("deptype = 'e'") && sql.contains("LIMIT 10001"));
    Ok(())
}
