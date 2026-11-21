use crate::drain;
use crate::fake::Reply;
use crate::migrate::committed;
use crate::query::client_with;
use crate::types::Handler;
use core_pg::error::PgError;
use core_pg::migrate::{
    check_search_paths, cut_signature, cut_sql, digest_of, functions_sql, migrate, read_search_paths, Migration, CUT_MARKER, MAX_APPLIED_ROWS,
    MAX_ROW_CHARS, MAX_SIGNATURE_CHARS,
};
use std::error::Error;
use std::sync::Arc;
use std::time::Duration;


const DEADLINE: Duration = Duration::from_secs(30);


const NAMESPACE: &str = "store";


const GOOD: &str = "search_path=pg_catalog, public, pg_temp";


const SHORT_BAD: usize = 144;


const LONG_BAD: usize = 300;


const EXPECTED_SQL: &str = "\
    SELECT CASE WHEN pg_catalog.char_length(p.oid::pg_catalog.regprocedure::pg_catalog.text) \
    OPERATOR(pg_catalog.>) 256 THEN pg_catalog.left(p.oid::pg_catalog.regprocedure::pg_catalog.text, 255) \
    OPERATOR(pg_catalog.||) '…' ELSE p.oid::pg_catalog.regprocedure::pg_catalog.text END, CASE WHEN \
    pg_catalog.char_length(coalesce((SELECT s FROM pg_catalog.unnest(p.proconfig) AS s WHERE \
    pg_catalog.starts_with(s, 'search_path=') LIMIT 1), '')) OPERATOR(pg_catalog.>) 256 THEN \
    pg_catalog.left(coalesce((SELECT s FROM pg_catalog.unnest(p.proconfig) AS s WHERE pg_catalog.starts_with(s, \
    'search_path=') LIMIT 1), ''), 255) OPERATOR(pg_catalog.||) '…' ELSE coalesce((SELECT s FROM \
    pg_catalog.unnest(p.proconfig) AS s WHERE pg_catalog.starts_with(s, 'search_path=') LIMIT 1), '') END FROM \
    pg_catalog.pg_proc p WHERE p.pronamespace OPERATOR(pg_catalog.=) 'public'::pg_catalog.regnamespace AND \
    p.prokind OPERATOR(pg_catalog.=) ANY (ARRAY['f'::pg_catalog.\"char\", 'p'::pg_catalog.\"char\"]) AND NOT EXISTS \
    (SELECT 1 FROM pg_catalog.pg_depend d JOIN pg_catalog.pg_extension x ON x.oid OPERATOR(pg_catalog.=) \
    d.refobjid WHERE d.classid OPERATOR(pg_catalog.=) 'pg_catalog.pg_proc'::pg_catalog.regclass AND d.objid \
    OPERATOR(pg_catalog.=) p.oid AND d.refclassid OPERATOR(pg_catalog.=) \
    'pg_catalog.pg_extension'::pg_catalog.regclass AND d.deptype OPERATOR(pg_catalog.=) 'e'::pg_catalog.\"char\" AND \
    x.extowner OPERATOR(pg_catalog.<>) (SELECT r.oid FROM pg_catalog.pg_roles r WHERE r.rolname \
    OPERATOR(pg_catalog.=) current_user)) ORDER BY 1 LIMIT 10001";


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
    committed(Arc::new(move |sql| {
        if sql.contains("information_schema.columns") {
            Reply::Rows(vec![vec!["namespace".to_owned()]])
        } else if sql.contains("FROM public.schema_migrations") {
            Reply::Rows(if applied {
                vec![vec![NAMESPACE.to_owned(), FIRST.version.to_owned(), digest_of(FIRST.sql)]]
            } else {
                Vec::new()
            })
        } else if sql.contains("FROM pg_catalog.pg_proc") {
            functions.clone()
        } else {
            Reply::Done
        }
    }))
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
async fn a_signature_over_the_limit_keeps_its_prefix_and_ends_with_the_marker() -> Result<(), Box<dyn Error>> {
    let cases = [SHORT_BAD, MAX_ROW_CHARS, LONG_BAD].map(|length| "a".repeat(length));
    let cut: Vec<String> = cases.iter().map(|signature| cut_signature(signature)).collect();
    assert!(cut
        .iter()
        .all(|text| text.chars().count() == MAX_SIGNATURE_CHARS && text.ends_with(CUT_MARKER)));
    assert!(cut.iter().all(|text| text.starts_with(&"a".repeat(MAX_SIGNATURE_CHARS - 1))));
    let exact = "b".repeat(MAX_SIGNATURE_CHARS);
    assert_eq!(cut_signature(&exact), exact);
    let named = check_search_paths(&[("c".repeat(SHORT_BAD), String::new())]);
    assert!(matches!(&named, Err(PgError::FunctionSearchPath { functions, .. }) if functions.ends_with(CUT_MARKER)));
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
    assert!(sql.contains("'public'::pg_catalog.regnamespace") && sql.contains("pg_catalog.pg_extension") && sql.contains("LIMIT 10001"));
    Ok(())
}


#[tokio::test]
async fn the_whole_statement_is_pinned_so_every_qualification_is_a_failing_mutant() -> Result<(), Box<dyn Error>> {
    assert_eq!(functions_sql(), EXPECTED_SQL);
    Ok(())
}


#[tokio::test]
async fn a_cut_row_ends_with_a_visible_marker() -> Result<(), Box<dyn Error>> {
    let sql = cut_sql("x");
    assert!(sql.contains("pg_catalog.char_length(x) OPERATOR(pg_catalog.>) 256") && sql.contains("pg_catalog.left(x, 255)"));
    assert!(sql.contains("OPERATOR(pg_catalog.||) '…' ELSE x END"));
    Ok(())
}
