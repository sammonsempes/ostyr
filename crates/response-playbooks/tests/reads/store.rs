use crate::fixture::{executor, seed, EMPTY_TRACE, OTHER_TENANT, TENANT};
use crate::memory::{run_id, Db};
use crate::types::TestResult;
use alerts::types::{Row, RowFuture};
use core_pg::scope::TenantScope;
use response_playbooks::api_model::RunPage;
use response_playbooks::error::ReadError;
use response_playbooks::runs_read::{
    clean_element, clean_trace, decode_detail, decode_meta, get_run, is_run_id, list_runs, parse_cursor, parse_limit, GET_SQL, LIST_FIRST_SQL,
    LIST_NEXT_SQL, MAX_CURSOR_DIGITS, TRACE_TEXT_LIMIT,
};
use serde_json::{json, Value};
use std::future::ready;
use std::sync::Mutex;


const MARKER: &str = "SECRETVALUE-7f3a";


const PAGE: usize = 2;


const THIRD: usize = 2;


const EXTRA_ROWS: usize = 2;


const SEQ_2: i64 = 2;


const SEQ_3: i64 = 3;


const SEQ_4: i64 = 4;


const SEQ_5: i64 = 5;


const SEQ_9: i64 = 9;


const SEQ_99: i64 = 99;


const SEQ_123: i64 = 123;


const THREE_CELLS: usize = 3;


const TEXT_COLUMN: usize = 5;


const CREATED_COLUMN: usize = 6;


const SEQ_COLUMN: usize = 7;


const DEFAULT_SIZE: usize = 50;


const MAX_SIZE: usize = 100;


const OVER_SIZE: usize = 101;


const COUNT_VALUE: i64 = 5;


const OMITTED_EVENTS: i64 = 3;


const ODD_KIND: i64 = 7;


const SEEDED: i64 = 5;


fn page(after: Option<i64>, size: usize) -> RunPage {
    RunPage { after, size }
}


fn seeded() -> Db {
    let db = Db::default();
    (1..=SEEDED).for_each(|seq| seed(&db, TENANT, 'a', seq, EMPTY_TRACE));
    (1..=PAGE as i64).for_each(|seq| seed(&db, OTHER_TENANT, 'b', seq + SEEDED, EMPTY_TRACE));
    db
}


fn fixed(rows: Vec<Row>) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'static> + Sync {
    move |_scope, _sql, _params| -> RowFuture<'static> { Box::pin(ready(Ok(rows.clone()))) }
}


fn cells(count: usize) -> Row {
    (0..count).map(|index| index.to_string()).collect()
}


fn meta_row(id: &str) -> Row {
    [id, "alert", "pb", "dry_run", "completed", "1", "2", "3"].map(str::to_owned).to_vec()
}


#[tokio::test]
async fn a_list_pages_newest_first_inside_the_tenant() -> TestResult {
    let db = seeded();
    let first = list_runs(&executor(&db), TENANT, page(None, PAGE)).await?;
    assert_eq!(first.runs.iter().map(|run| run.seq).collect::<Vec<_>>(), vec![SEQ_5, SEQ_4]);
    assert_eq!(first.next, Some(SEQ_4));
    let second = list_runs(&executor(&db), TENANT, page(first.next, PAGE)).await?;
    assert_eq!(second.runs.iter().map(|run| run.seq).collect::<Vec<_>>(), vec![SEQ_3, SEQ_2]);
    assert_eq!(second.next, Some(SEQ_2));
    let last = list_runs(&executor(&db), TENANT, page(second.next, PAGE)).await?;
    assert_eq!(last.runs.iter().map(|run| run.seq).collect::<Vec<_>>(), vec![1]);
    assert_eq!(last.next, None);
    assert!(first.runs.iter().all(|run| run.id.starts_with('a')));
    Ok(())
}


#[tokio::test]
async fn a_full_final_page_has_no_next_cursor() -> TestResult {
    let db = seeded();
    let all = list_runs(&executor(&db), TENANT, page(None, SEEDED as usize)).await?;
    assert_eq!(all.runs.len(), SEEDED as usize);
    assert_eq!(all.next, None);
    Ok(())
}


#[tokio::test]
async fn a_forged_cursor_stays_inside_the_tenant() -> TestResult {
    let db = seeded();
    let forged = list_runs(&executor(&db), OTHER_TENANT, page(Some(i64::MAX), PAGE)).await?;
    assert!(forged.runs.iter().all(|run| run.id.starts_with('b')));
    let mine = list_runs(&executor(&db), TENANT, page(Some(i64::MAX), PAGE)).await?;
    assert!(mine.runs.iter().all(|run| run.id.starts_with('a')));
    Ok(())
}


#[tokio::test]
async fn the_statements_carry_the_size_plus_one_and_the_cursor() -> TestResult {
    let seen: Mutex<Vec<(&'static str, Vec<String>)>> = Mutex::default();
    let recorder = |_scope: TenantScope, sql: &'static str, params: Vec<String>| -> RowFuture<'static> {
        seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner).push((sql, params));
        Box::pin(ready(Ok(Vec::new())))
    };
    list_runs(&recorder, TENANT, page(None, PAGE)).await?;
    list_runs(&recorder, TENANT, page(Some(SEQ_9), PAGE)).await?;
    let held = seen.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    assert_eq!(held.first(), Some(&(LIST_FIRST_SQL, vec!["3".to_owned()])));
    assert_eq!(held.get(1), Some(&(LIST_NEXT_SQL, vec!["9".to_owned(), "3".to_owned()])));
    Ok(())
}


#[tokio::test]
async fn a_bad_size_or_tenant_is_refused_before_the_store() -> TestResult {
    let failing = |_scope: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'static> {
        Box::pin(ready(Err(core_pg::error::PgError::ConnectTimeout { seconds: 1 })))
    };
    let db = Db::default();
    assert!(matches!(
        list_runs(&executor(&db), TENANT, page(None, 0)).await,
        Err(ReadError::BadLimit { .. })
    ));
    assert!(matches!(
        list_runs(&executor(&db), TENANT, page(None, OVER_SIZE)).await,
        Err(ReadError::BadLimit { .. })
    ));
    assert!(matches!(list_runs(&executor(&db), "-x", page(None, 1)).await, Err(ReadError::Pg(_))));
    assert!(matches!(get_run(&executor(&db), "-x", &run_id('a', 1)).await, Err(ReadError::Pg(_))));
    assert!(matches!(list_runs(&failing, TENANT, page(None, 1)).await, Err(ReadError::Pg(_))));
    assert!(matches!(get_run(&failing, TENANT, &run_id('a', 1)).await, Err(ReadError::Pg(_))));
    Ok(())
}


#[tokio::test]
async fn a_store_answer_this_version_cannot_read_is_refused() -> TestResult {
    let too_many = fixed(vec![meta_row("x"); PAGE + EXTRA_ROWS]);
    assert!(matches!(list_runs(&too_many, TENANT, page(None, PAGE)).await, Err(ReadError::BadRow)));
    let short = fixed(vec![cells(THREE_CELLS)]);
    assert!(matches!(list_runs(&short, TENANT, page(None, PAGE)).await, Err(ReadError::BadRow)));
    let mut text = meta_row("x");
    text.splice(TEXT_COLUMN..TEXT_COLUMN + 1, ["many".to_owned()]);
    assert!(matches!(decode_meta(&text), Err(ReadError::BadRow)));
    let mut created = meta_row("x");
    created.splice(CREATED_COLUMN..CREATED_COLUMN + 1, ["soon".to_owned()]);
    assert!(matches!(decode_meta(&created), Err(ReadError::BadRow)));
    let mut seq = meta_row("x");
    seq.splice(SEQ_COLUMN..SEQ_COLUMN + 1, ["later".to_owned()]);
    assert!(matches!(decode_meta(&seq), Err(ReadError::BadRow)));
    Ok(())
}


#[test]
fn a_cursor_is_decimal_digits_that_fit_a_bigint() -> TestResult {
    assert!(matches!(parse_cursor("123"), Ok(SEQ_123)));
    assert!(matches!(parse_cursor("0"), Ok(0)));
    ["", "abc", "-1", "+1", "1 ", "1.5", "9999999999999999999", "٣"]
        .into_iter()
        .for_each(|text| assert!(matches!(parse_cursor(text), Err(ReadError::BadCursor)), "{text}"));
    let long = "1".repeat(MAX_CURSOR_DIGITS + 1);
    assert!(matches!(parse_cursor(&long), Err(ReadError::BadCursor)));
    Ok(())
}


#[test]
fn a_limit_is_one_to_one_hundred_digits() -> TestResult {
    assert!(matches!(parse_limit(None, DEFAULT_SIZE), Ok(DEFAULT_SIZE)));
    assert!(matches!(parse_limit(Some("1"), DEFAULT_SIZE), Ok(1)));
    assert!(matches!(parse_limit(Some("100"), DEFAULT_SIZE), Ok(MAX_SIZE)));
    ["0", "101", "-1", "+5", "x", "", "99999999999999999999999"]
        .into_iter()
        .for_each(|text| assert!(matches!(parse_limit(Some(text), DEFAULT_SIZE), Err(ReadError::BadLimit { .. })), "{text}"));
    Ok(())
}


#[test]
fn a_run_id_is_sixty_four_lowercase_hex_characters() -> TestResult {
    assert!(is_run_id(&run_id('a', 1)));
    assert!(!is_run_id(&run_id('A', 1)));
    assert!(!is_run_id(&run_id('g', 1)));
    assert!(!is_run_id("abc"));
    assert!(!is_run_id(&format!("{}x", run_id('a', 1))));
    Ok(())
}


#[tokio::test]
async fn a_get_reads_the_tenants_run_only() -> TestResult {
    let db = seeded();
    let found = get_run(&executor(&db), TENANT, &run_id('a', SEQ_3)).await?.ok_or("no run")?;
    assert_eq!(found.meta.seq, SEQ_3);
    assert_eq!(found.trace, json!([]));
    assert!(get_run(&executor(&db), TENANT, &run_id('b', SEEDED + 1)).await?.is_none());
    assert!(get_run(&executor(&db), TENANT, &run_id('a', SEQ_99)).await?.is_none());
    Ok(())
}


#[tokio::test]
async fn a_malformed_id_never_reaches_the_store() -> TestResult {
    let counted: Mutex<usize> = Mutex::default();
    let recorder = |_scope: TenantScope, _sql: &'static str, _params: Vec<String>| -> RowFuture<'static> {
        *counted.lock().unwrap_or_else(std::sync::PoisonError::into_inner) += 1;
        Box::pin(ready(Ok(Vec::new())))
    };
    assert!(get_run(&recorder, TENANT, "x' OR '1'='1").await?.is_none());
    assert_eq!(*counted.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 0);
    assert!(get_run(&recorder, TENANT, &run_id('a', 1)).await?.is_none());
    assert_eq!(*counted.lock().unwrap_or_else(std::sync::PoisonError::into_inner), 1);
    assert!(GET_SQL.contains("tenant = $1"));
    Ok(())
}


#[tokio::test]
async fn a_get_answer_this_version_cannot_read_is_refused() -> TestResult {
    let id = run_id('a', 1);
    let mut detail = meta_row(&id);
    detail.push("[]".to_owned());
    let twice = fixed(vec![detail.clone(), detail.clone()]);
    assert!(matches!(get_run(&twice, TENANT, &id).await, Err(ReadError::BadRow)));
    let other = fixed(vec![{
        let mut row = meta_row(&run_id('a', SEQ_2));
        row.push("[]".to_owned());
        row
    }]);
    assert!(matches!(get_run(&other, TENANT, &id).await, Err(ReadError::BadRow)));
    assert!(matches!(decode_detail(&id, &[]), Err(ReadError::BadRow)));
    assert!(matches!(decode_detail(&id, &cells(THREE_CELLS)), Err(ReadError::BadRow)));
    let mut bad_trace = meta_row(&id);
    bad_trace.push("{".to_owned());
    assert!(matches!(decode_detail(&id, &bad_trace), Err(ReadError::BadRow)));
    Ok(())
}


#[test]
fn a_trace_is_rebuilt_from_its_fixed_keys() -> TestResult {
    let stored = json!([
        {"kind": "action", "outcome": "allowed", "path": "steps.0", "action": "block_ip", "connector": "fw", "step": "s",
         "params": {"ip": "ip", "message": MARKER, "count": COUNT_VALUE, "flag": "boolean"}, "reason": MARKER, "events": MARKER},
        {"kind": "omitted", "events": OMITTED_EVENTS},
        {"kind": ODD_KIND, "outcome": null, "params": "not an object", "events": -1}
    ])
    .to_string();
    let cleaned = clean_trace(&stored)?;
    let text = cleaned.to_string();
    assert!(!text.contains(MARKER), "{text}");
    let first = cleaned.get(0).ok_or("no first")?;
    assert_eq!(
        first.get("params"),
        Some(&json!({"ip": "ip", "message": "unknown", "count": "unknown", "flag": "boolean"}))
    );
    assert_eq!(first.get("action"), Some(&json!("block_ip")));
    assert_eq!(first.get("reason"), None);
    assert_eq!(first.get("events"), None);
    assert_eq!(cleaned.get(1), Some(&json!({"kind": "omitted", "events": OMITTED_EVENTS})));
    assert_eq!(cleaned.get(THIRD), Some(&json!({})));
    Ok(())
}


#[test]
fn every_catalogue_kind_word_survives_and_a_value_never_does() -> TestResult {
    let kinds = ["string", "integer", "boolean", "ip", "domain", "duration"];
    let params: serde_json::Map<String, Value> = kinds.iter().map(|word| ((*word).to_owned(), json!(word))).collect();
    let cleaned = clean_element(&json!({"kind": "action", "params": params}))?;
    assert_eq!(cleaned.get("params"), Some(&Value::Object(params)));
    let value = clean_element(&json!({"params": {"target": "10.0.0.1"}}))?;
    assert_eq!(value.get("params"), Some(&json!({"target": "unknown"})));
    Ok(())
}


#[test]
fn a_trace_that_is_not_an_array_of_objects_or_is_too_long_is_refused() -> TestResult {
    assert!(matches!(clean_trace("{}"), Err(ReadError::BadRow)));
    assert!(matches!(clean_trace("[1]"), Err(ReadError::BadRow)));
    assert!(matches!(clean_trace("nope"), Err(ReadError::BadRow)));
    let long = format!("[\"{}\"]", "x".repeat(TRACE_TEXT_LIMIT));
    assert!(matches!(clean_trace(&long), Err(ReadError::BadRow)));
    Ok(())
}


#[test]
fn the_list_statements_order_by_the_numeric_column_not_the_text_output() -> TestResult {
    [LIST_FIRST_SQL, LIST_NEXT_SQL].iter().for_each(|sql| {
        assert!(sql.contains("run_seq::text AS seq_text"), "{sql}");
        assert!(sql.contains("ORDER BY playbook_runs.run_seq DESC"), "{sql}");
    });
    Ok(())
}
