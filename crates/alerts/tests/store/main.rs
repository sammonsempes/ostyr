mod memory;
mod types;


use alerts::error::StoreError;
use alerts::id::{alert_id, is_alert_id, ID_HEX_LENGTH};
use alerts::model::{Alert, Cursor, Page, Severity, Summary, SEVERITY_COLUMN};
use alerts::store::{
    check_alert, check_page, format_cursor, get_alert, insert_alerts, list_alerts, parse_cursor, summarise, CREATED_COLUMN, EVENT_IDS_COLUMN,
    FIRST_SQL, GET_SQL, INSERT_SQL, MAX_ALERTS_PER_INSERT, MAX_CREATED_MICROS, MAX_ENTITY_CHARS, MAX_EVENT_IDS, MAX_EVENT_ID_CHARS,
    MAX_EVENT_TIME_CHARS, MAX_PAGE_SIZE, MAX_RULE_ID_CHARS, MAX_SUMMARY_BYTES, MAX_TITLE_CHARS, MIGRATIONS, MIGRATION_NAMESPACE, NEXT_SQL,
    ORIGINAL_BYTES_COLUMN, TRUNCATED_COLUMN,
};
use alerts::types::{Row, RowFuture};
use core_pg::error::PgError;
use core_pg::migrate::{check_embedded, check_namespace};
use core_pg::scope::{tenant_scope, TenantScope};
use memory::{handle, lock, Db, Forced};
use serde_json::json;
use std::future::ready;
use types::{Mutation, TestResult};


const KNOWN_ID: &str = "2d6c7e2fdf972aab0077338ff3c04044ccb108f41661aa365bea425f0b894fee";


const TWO: usize = 2;


const SEVEN: usize = 7;


const SMALL_PAGE: usize = 3;


const BASE_TIME: u64 = 1_700_000_000_000_000;


const HUGE_EVENT_COUNT: usize = 10_000;


const ACCENTED_REPEAT: usize = 5_000;


pub fn executor<'a>(db: &'a Db) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> { Box::pin(ready(handle(db, &scope, sql, &params))) }
}


pub fn events(names: &[&str]) -> Vec<String> {
    names.iter().map(|name| (*name).to_owned()).collect()
}


pub fn alert(tenant: &str, rule: &str, names: &[&str], created: u64) -> Alert {
    let event_ids = events(names);
    Alert {
        id: alert_id(tenant, rule, &event_ids),
        tenant: tenant.to_owned(),
        rule_id: rule.to_owned(),
        rule_title: "Whoami executed".to_owned(),
        severity: Severity::High,
        event_time: "2026-11-10T10:00:00Z".to_owned(),
        created_micros: created,
        host_name: Some("host-1".to_owned()),
        user_name: None,
        event_ids,
        summary: summarise(&json!({"process": {"name": "whoami"}})),
    }
}


pub fn stored(db: &Db, tenant: &str) -> usize {
    lock(&db.tenants).get(tenant).map_or(0, |table| table.len())
}


pub fn sent(db: &Db) -> usize {
    lock(&db.statements).len()
}


#[test]
fn id_matches_the_published_vector_and_ignores_event_order() -> TestResult {
    assert_eq!(alert_id("a", "r", &events(&["e2", "e1"])), KNOWN_ID);
    assert_eq!(alert_id("a", "r", &events(&["e1", "e2"])), KNOWN_ID);
    assert!(is_alert_id(KNOWN_ID));
    Ok(())
}


#[test]
fn id_changes_with_tenant_rule_and_event_set() -> TestResult {
    let base = alert_id("a", "r", &events(&["e1", "e2"]));
    assert_ne!(base, alert_id("b", "r", &events(&["e1", "e2"])));
    assert_ne!(base, alert_id("a", "s", &events(&["e1", "e2"])));
    assert_ne!(base, alert_id("a", "r", &events(&["e1", "e3"])));
    assert_ne!(base, alert_id("a", "r", &events(&["e1"])));
    assert_ne!(alert_id("ab", "c", &events(&["e"])), alert_id("a", "bc", &events(&["e"])));
    assert_ne!(alert_id("a", "r", &events(&["xy"])), alert_id("a", "r", &events(&["x", "y"])));
    Ok(())
}


#[test]
fn id_syntax_is_64_lowercase_hex() -> TestResult {
    assert!(!is_alert_id(""));
    assert!(!is_alert_id(&KNOWN_ID.to_uppercase()));
    assert!(!is_alert_id(&KNOWN_ID.replace('2', "g")));
    assert!(!is_alert_id(&KNOWN_ID.chars().take(ID_HEX_LENGTH - 1).collect::<String>()));
    Ok(())
}


#[test]
fn severity_round_trips_and_refuses_unknown_names() -> TestResult {
    [
        Severity::Informational,
        Severity::Low,
        Severity::Medium,
        Severity::High,
        Severity::Critical,
    ]
    .iter()
    .try_for_each(|severity| severity.to_string().parse::<Severity>().map(|parsed| assert_eq!(parsed, *severity)))?;
    assert!(matches!("urgent".parse::<Severity>(), Err(StoreError::BadRow { .. })));
    Ok(())
}


#[test]
fn migrations_are_valid_and_namespaced() -> TestResult {
    check_embedded(&MIGRATIONS)?;
    check_namespace(MIGRATION_NAMESPACE)?;
    assert!(MIGRATIONS.iter().all(|migration| migration.sql.contains("PRIMARY KEY (tenant, id)")));
    assert!(INSERT_SQL.contains("ON CONFLICT (tenant, id) DO NOTHING"));
    [FIRST_SQL, NEXT_SQL, GET_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("WHERE tenant = $1")));
    Ok(())
}


#[tokio::test]
async fn insert_is_idempotent_and_counts_new_rows() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let batch = vec![alert("acme", "r1", &["e1"], BASE_TIME), alert("acme", "r2", &["e2"], BASE_TIME)];
    assert_eq!(insert_alerts(&exec, &scope, &batch).await?, TWO);
    assert_eq!(insert_alerts(&exec, &scope, &batch).await?, 0);
    assert_eq!(stored(&db, "acme"), TWO);
    Ok(())
}


#[tokio::test]
async fn the_same_alert_inserted_twice_in_one_call_or_concurrently_is_one_row() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let one = alert("acme", "r1", &["e1"], BASE_TIME);
    let pair = [one.clone(), one.clone()];
    let (first, second) = tokio::join!(
        insert_alerts(&exec, &scope, std::slice::from_ref(&one)),
        insert_alerts(&exec, &scope, &pair)
    );
    assert_eq!(first? + second?, 1);
    assert_eq!(stored(&db, "acme"), 1);
    Ok(())
}


#[tokio::test]
async fn an_empty_insert_sends_nothing() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    assert_eq!(insert_alerts(&exec, &tenant_scope("acme")?, &[]).await?, 0);
    assert_eq!(sent(&db), 0);
    Ok(())
}


#[tokio::test]
async fn too_many_alerts_are_refused_and_nothing_is_written() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let one = alert("acme", "r1", &["e1"], BASE_TIME);
    let batch = vec![one; MAX_ALERTS_PER_INSERT + 1];
    let error = insert_alerts(&exec, &scope, &batch).await.err().ok_or("accepted")?;
    assert!(
        matches!(error, StoreError::TooManyAlerts { limit } if limit == MAX_ALERTS_PER_INSERT),
        "{error}"
    );
    assert_eq!(sent(&db), 0);
    let exact = vec![one_of(&batch)?; MAX_ALERTS_PER_INSERT];
    assert_eq!(insert_alerts(&exec, &scope, &exact).await?, 1);
    Ok(())
}


pub fn one_of(batch: &[Alert]) -> Result<Alert, Box<dyn std::error::Error>> {
    Ok(batch.first().ok_or("empty")?.clone())
}


pub fn refused(scope: &TenantScope, mutate: impl Fn(&mut Alert)) -> Result<StoreError, Box<dyn std::error::Error>> {
    let mut candidate = alert("acme", "r1", &["e1"], BASE_TIME);
    mutate(&mut candidate);
    Ok(check_alert(scope, &candidate).err().ok_or("accepted")?)
}


#[tokio::test]
async fn every_bound_is_refused_before_any_sql() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let cases: Vec<Mutation> = vec![
        Box::new(|candidate| candidate.tenant = "other".to_owned()),
        Box::new(|candidate| candidate.rule_id = String::new()),
        Box::new(|candidate| candidate.rule_id = "r".repeat(MAX_RULE_ID_CHARS + 1)),
        Box::new(|candidate| candidate.rule_title = "t".repeat(MAX_TITLE_CHARS + 1)),
        Box::new(|candidate| candidate.event_time = "t".repeat(MAX_EVENT_TIME_CHARS + 1)),
        Box::new(|candidate| candidate.host_name = Some("h".repeat(MAX_ENTITY_CHARS + 1))),
        Box::new(|candidate| candidate.user_name = Some(String::new())),
        Box::new(|candidate| candidate.user_name = Some("u".repeat(MAX_ENTITY_CHARS + 1))),
        Box::new(|candidate| candidate.event_ids = Vec::new()),
        Box::new(|candidate| candidate.event_ids = (0..HUGE_EVENT_COUNT).map(|index| index.to_string()).collect()),
        Box::new(|candidate| candidate.event_ids = vec!["e".repeat(MAX_EVENT_ID_CHARS + 1)]),
        Box::new(|candidate| candidate.summary.text = "s".repeat(MAX_SUMMARY_BYTES + 1)),
        Box::new(|candidate| candidate.summary.original_bytes = 0),
        Box::new(|candidate| candidate.summary.truncated = true),
        Box::new(|candidate| candidate.summary.original_bytes += 1),
        Box::new(|candidate| candidate.created_micros = MAX_CREATED_MICROS + 1),
        Box::new(|candidate| candidate.id = alert_id("acme", "r1", &events(&["other"]))),
    ];
    let failures = cases
        .iter()
        .map(|mutate| refused(&scope, mutate))
        .collect::<Result<Vec<StoreError>, _>>()?;
    assert!(matches!(failures.first(), Some(StoreError::TenantMismatch)));
    assert!(matches!(failures.get(1), Some(StoreError::FieldEmpty { field: "rule_id" })));
    assert!(matches!(failures.get(TWO), Some(StoreError::FieldTooLong { field: "rule_id", .. })));
    assert!(matches!(failures.last(), Some(StoreError::IdMismatch)));
    assert!(failures.iter().any(|failure| matches!(failure, StoreError::BadEventCount { .. })));
    assert!(failures.iter().any(|failure| matches!(failure, StoreError::BadSummary)));
    assert!(failures.iter().any(|failure| matches!(failure, StoreError::BadCreated)));
    let mut hostile = alert("acme", "r1", &["e1"], BASE_TIME);
    hostile.event_ids = (0..HUGE_EVENT_COUNT).map(|index| index.to_string()).collect();
    hostile.rule_title = "t".repeat(MAX_TITLE_CHARS + 1);
    let error = insert_alerts(&exec, &scope, &[alert("acme", "ok", &["e1"], BASE_TIME), hostile])
        .await
        .err()
        .ok_or("accepted")?;
    assert!(matches!(error, StoreError::FieldTooLong { .. }));
    assert_eq!(sent(&db), 0);
    assert_eq!(stored(&db, "acme"), 0);
    Ok(())
}


#[test]
fn the_event_count_limit_is_inclusive() -> TestResult {
    let scope = tenant_scope("acme")?;
    let names: Vec<String> = (0..MAX_EVENT_IDS).map(|index| index.to_string()).collect();
    let mut candidate = alert("acme", "r1", &["e1"], BASE_TIME);
    candidate.event_ids = names;
    candidate.id = alert_id("acme", "r1", &candidate.event_ids);
    check_alert(&scope, &candidate)?;
    candidate.event_ids.push("extra".to_owned());
    assert!(matches!(check_alert(&scope, &candidate), Err(StoreError::BadEventCount { .. })));
    Ok(())
}


#[test]
fn multibyte_fields_are_counted_in_characters() -> TestResult {
    let scope = tenant_scope("acme")?;
    let mut candidate = alert("acme", "r1", &["e1"], BASE_TIME);
    candidate.rule_title = "\u{e9}".repeat(MAX_TITLE_CHARS);
    check_alert(&scope, &candidate)?;
    candidate.rule_title = "\u{e9}".repeat(MAX_TITLE_CHARS + 1);
    assert!(matches!(check_alert(&scope, &candidate), Err(StoreError::FieldTooLong { .. })));
    Ok(())
}


#[test]
fn a_small_summary_is_kept_whole() -> TestResult {
    let summary = summarise(&json!({"a": 1}));
    let text = "{\"a\":1}".to_owned();
    let original_bytes = text.len() as u64;
    assert_eq!(
        summary,
        Summary {
            text,
            truncated: false,
            original_bytes
        }
    );
    Ok(())
}


#[test]
fn a_large_summary_is_cut_visibly_on_a_character_boundary() -> TestResult {
    let summary = summarise(&json!({"blob": "x".repeat(MAX_SUMMARY_BYTES * TWO)}));
    assert!(summary.truncated);
    assert_eq!(summary.text.len(), MAX_SUMMARY_BYTES);
    assert!(summary.original_bytes > MAX_SUMMARY_BYTES as u64);
    let accented = summarise(&json!("\u{e9}".repeat(ACCENTED_REPEAT)));
    assert!(accented.truncated);
    assert!(accented.text.len() < MAX_SUMMARY_BYTES);
    assert_eq!(accented.original_bytes, (ACCENTED_REPEAT * TWO + TWO) as u64);
    check_alert(
        &tenant_scope("acme")?,
        &Alert {
            summary,
            ..alert("acme", "r1", &["e1"], BASE_TIME)
        },
    )?;
    Ok(())
}


#[tokio::test]
async fn a_cut_summary_survives_a_round_trip_with_its_flag_and_size() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let mut big = alert("acme", "r1", &["e1"], BASE_TIME);
    big.summary = summarise(&json!({"blob": "x".repeat(MAX_SUMMARY_BYTES * TWO)}));
    big.user_name = Some("root".to_owned());
    insert_alerts(&exec, &scope, std::slice::from_ref(&big)).await?;
    let back = get_alert(&exec, &scope, &big.id).await?.ok_or("missing")?;
    assert_eq!(back, big);
    assert!(back.summary.truncated);
    Ok(())
}


pub fn ids(page: &alerts::model::AlertPage) -> Vec<String> {
    page.alerts.iter().map(|found| found.id.clone()).collect()
}


#[tokio::test]
async fn keyset_pagination_has_no_duplicate_and_no_gap() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let batch: Vec<Alert> = (0..SEVEN)
        .map(|index| alert("acme", "r1", &[&format!("e{index}")], BASE_TIME + (index as u64 / TWO as u64)))
        .collect();
    insert_alerts(&exec, &scope, &batch).await?;
    let mut expected: Vec<&Alert> = batch.iter().collect();
    expected.sort_by(|left, right| (right.created_micros, &right.id).cmp(&(left.created_micros, &left.id)));
    let expected_ids: Vec<String> = expected.iter().map(|found| found.id.clone()).collect();
    let mut seen: Vec<String> = Vec::new();
    let mut after = None;
    let mut pages = 0;
    while pages < SEVEN {
        let page = list_alerts(
            &exec,
            &scope,
            &Page {
                after: after.clone(),
                size: SMALL_PAGE,
            },
        )
        .await?;
        seen.extend(ids(&page));
        pages += 1;
        after = page.next;
        if after.is_none() {
            pages = SEVEN;
        }
    }
    assert_eq!(seen, expected_ids);
    Ok(())
}


#[tokio::test]
async fn the_last_page_has_no_cursor_even_when_it_is_exactly_full() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let batch: Vec<Alert> = (0..SMALL_PAGE)
        .map(|index| alert("acme", "r1", &[&format!("e{index}")], BASE_TIME + index as u64))
        .collect();
    insert_alerts(&exec, &scope, &batch).await?;
    let page = list_alerts(
        &exec,
        &scope,
        &Page {
            after: None,
            size: SMALL_PAGE,
        },
    )
    .await?;
    assert_eq!(page.alerts.len(), SMALL_PAGE);
    assert!(page.next.is_none());
    let short = list_alerts(
        &exec,
        &scope,
        &Page {
            after: None,
            size: SMALL_PAGE - 1,
        },
    )
    .await?;
    let cursor = short.next.ok_or("no cursor")?;
    let rest = list_alerts(
        &exec,
        &scope,
        &Page {
            after: Some(cursor),
            size: SMALL_PAGE,
        },
    )
    .await?;
    assert_eq!(rest.alerts.len(), 1);
    assert!(rest.next.is_none());
    Ok(())
}


#[tokio::test]
async fn bad_pages_and_cursors_are_refused_before_any_sql() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let good_cursor = Cursor {
        created_micros: 1,
        id: KNOWN_ID.to_owned(),
    };
    let pages = [
        Page { after: None, size: 0 },
        Page {
            after: None,
            size: MAX_PAGE_SIZE + 1,
        },
        Page {
            after: None,
            size: usize::MAX,
        },
        Page {
            after: Some(Cursor {
                id: "forged".to_owned(),
                ..good_cursor.clone()
            }),
            size: 1,
        },
        Page {
            after: Some(Cursor {
                created_micros: MAX_CREATED_MICROS + 1,
                ..good_cursor.clone()
            }),
            size: 1,
        },
    ];
    pages.iter().try_for_each(|page| {
        assert!(check_page(page).is_err());
        Ok::<(), StoreError>(())
    })?;
    let first = list_alerts(&exec, &scope, &Page { after: None, size: 0 }).await.err().ok_or("accepted")?;
    assert!(matches!(first, StoreError::BadPageSize { limit } if limit == MAX_PAGE_SIZE));
    let second = list_alerts(
        &exec,
        &scope,
        &Page {
            after: Some(Cursor {
                id: "x".to_owned(),
                ..good_cursor
            }),
            size: 1,
        },
    )
    .await
    .err()
    .ok_or("accepted")?;
    assert!(matches!(second, StoreError::BadCursor));
    check_page(&Page {
        after: None,
        size: MAX_PAGE_SIZE,
    })?;
    assert_eq!(sent(&db), 0);
    Ok(())
}


#[test]
fn cursors_round_trip_and_refuse_hostile_text() -> TestResult {
    let cursor = Cursor {
        created_micros: BASE_TIME,
        id: KNOWN_ID.to_owned(),
    };
    assert_eq!(parse_cursor(&format_cursor(&cursor))?, cursor);
    let hostile = [
        format!("-5.{KNOWN_ID}"),
        format!("99999999999999999999999.{KNOWN_ID}"),
        format!("{}.{KNOWN_ID}", MAX_CREATED_MICROS + 1),
        format!("12.{}", KNOWN_ID.to_uppercase()),
        "12".to_owned(),
        String::new(),
        ".".to_owned(),
        format!("1e3.{KNOWN_ID}"),
    ];
    hostile
        .iter()
        .for_each(|text| assert!(matches!(parse_cursor(text), Err(StoreError::BadCursor)), "{text}"));
    Ok(())
}


#[tokio::test]
async fn get_finds_an_alert_and_refuses_a_bad_id() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let one = alert("acme", "r1", &["e1"], BASE_TIME);
    insert_alerts(&exec, &scope, std::slice::from_ref(&one)).await?;
    assert_eq!(get_alert(&exec, &scope, &one.id).await?, Some(one));
    assert_eq!(get_alert(&exec, &scope, KNOWN_ID).await?, None);
    let error = get_alert(&exec, &scope, "' OR 1=1 --").await.err().ok_or("accepted")?;
    assert!(matches!(error, StoreError::BadId));
    Ok(())
}


#[tokio::test]
async fn tenant_b_can_neither_get_nor_list_tenant_a_alerts() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope_a = tenant_scope("a")?;
    let scope_b = tenant_scope("b")?;
    let secret = alert("a", "r1", &["e1"], BASE_TIME);
    insert_alerts(&exec, &scope_a, std::slice::from_ref(&secret)).await?;
    assert_eq!(get_alert(&exec, &scope_b, &secret.id).await?, None);
    let listed = list_alerts(
        &exec,
        &scope_b,
        &Page {
            after: None,
            size: MAX_PAGE_SIZE,
        },
    )
    .await?;
    assert!(listed.alerts.is_empty());
    let forged = Cursor {
        created_micros: BASE_TIME + 1,
        id: secret.id.clone(),
    };
    let through_cursor = list_alerts(
        &exec,
        &scope_b,
        &Page {
            after: Some(forged),
            size: MAX_PAGE_SIZE,
        },
    )
    .await?;
    assert!(through_cursor.alerts.is_empty());
    let refused = insert_alerts(&exec, &scope_b, std::slice::from_ref(&secret))
        .await
        .err()
        .ok_or("accepted")?;
    assert!(matches!(refused, StoreError::TenantMismatch));
    assert_eq!(stored(&db, "b"), 0);
    let twin = alert("b", "r1", &["e1"], BASE_TIME);
    assert_ne!(twin.id, secret.id);
    insert_alerts(&exec, &scope_b, std::slice::from_ref(&twin)).await?;
    assert_eq!(get_alert(&exec, &scope_a, &twin.id).await?, None);
    assert_eq!(
        list_alerts(
            &exec,
            &scope_a,
            &Page {
                after: None,
                size: MAX_PAGE_SIZE
            }
        )
        .await?
        .alerts,
        vec![secret]
    );
    assert!(lock(&db.statements).iter().all(|(tenant, _sql)| tenant == "a" || tenant == "b"));
    Ok(())
}


#[tokio::test]
async fn a_database_failure_is_a_typed_error() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let one = alert("acme", "r1", &["e1"], BASE_TIME);
    lock(&db.forced).push_back(Forced::Fail);
    let error = insert_alerts(&exec, &scope, std::slice::from_ref(&one)).await.err().ok_or("accepted")?;
    assert!(matches!(error, StoreError::Pg(PgError::Server { .. })));
    assert_eq!(stored(&db, "acme"), 0);
    Ok(())
}


pub fn good_row() -> Row {
    let one = alert("acme", "r1", &["e1"], BASE_TIME);
    vec![
        one.id,
        one.rule_id,
        one.rule_title,
        "high".to_owned(),
        one.event_time,
        BASE_TIME.to_string(),
        "host-1".to_owned(),
        String::new(),
        "[\"e1\"]".to_owned(),
        one.summary.text,
        "false".to_owned(),
        one.summary.original_bytes.to_string(),
    ]
}


pub fn damaged(column: usize, value: &str) -> Row {
    let mut row = good_row();
    row.iter_mut()
        .enumerate()
        .filter(|(index, _cell)| *index == column)
        .for_each(|(_index, cell)| *cell = value.to_owned());
    row
}


#[tokio::test]
async fn malformed_rows_from_the_store_are_typed_errors() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let page = Page { after: None, size: 1 };
    let damages = vec![
        (vec![good_row()], true),
        (vec![damaged(TRUNCATED_COLUMN, "true")], true),
        (vec![good_row().into_iter().take(TWO).collect()], false),
        (vec![damaged(SEVERITY_COLUMN, "urgent")], false),
        (vec![damaged(CREATED_COLUMN, "-1")], false),
        (vec![damaged(EVENT_IDS_COLUMN, "not json")], false),
        (vec![damaged(TRUNCATED_COLUMN, "maybe")], false),
        (vec![damaged(ORIGINAL_BYTES_COLUMN, "many")], false),
    ];
    for (rows, good) in damages {
        lock(&db.forced).push_back(Forced::Rows(rows));
        assert_eq!(list_alerts(&exec, &scope, &page).await.is_ok(), good);
    }
    lock(&db.forced).push_back(Forced::Rows(Vec::new()));
    assert!(matches!(
        insert_alerts(&exec, &scope, &[alert("acme", "r1", &["e1"], BASE_TIME)]).await,
        Err(StoreError::BadRow { column: 0 })
    ));
    lock(&db.forced).push_back(Forced::Rows(vec![vec!["many".to_owned()]]));
    assert!(matches!(
        insert_alerts(&exec, &scope, &[alert("acme", "r1", &["e1"], BASE_TIME)]).await,
        Err(StoreError::BadNumber { .. })
    ));
    Ok(())
}


#[tokio::test]
async fn a_nul_character_in_any_field_is_refused_before_any_sql() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let cases: Vec<Mutation> = vec![
        Box::new(|candidate| candidate.rule_id = "r\u{0}".to_owned()),
        Box::new(|candidate| candidate.rule_title = "t\u{0}".to_owned()),
        Box::new(|candidate| candidate.event_time = "\u{0}".to_owned()),
        Box::new(|candidate| candidate.host_name = Some("h\u{0}h".to_owned())),
        Box::new(|candidate| candidate.user_name = Some("\u{0}".to_owned())),
        Box::new(|candidate| candidate.event_ids = vec!["e\u{0}".to_owned()]),
        Box::new(|candidate| candidate.summary.text = "{\"a\":\"\u{0}\"}".to_owned()),
    ];
    let failures = cases
        .iter()
        .map(|mutate| refused(&scope, mutate))
        .collect::<Result<Vec<StoreError>, _>>()?;
    assert!(failures.iter().all(|failure| matches!(failure, StoreError::NulByte { .. })));
    assert!(matches!(failures.last(), Some(StoreError::NulByte { field: "summary" })));
    let mut hostile = alert("acme", "ok2", &["e1"], BASE_TIME);
    hostile.host_name = Some("h\u{0}".to_owned());
    let error = insert_alerts(&exec, &scope, &[alert("acme", "ok", &["e1"], BASE_TIME), hostile])
        .await
        .err()
        .ok_or("accepted")?;
    assert!(matches!(error, StoreError::NulByte { field: "host_name" }));
    assert_eq!(sent(&db), 0);
    let honest = alert("acme", "ok", &["e1"], BASE_TIME);
    assert_eq!(insert_alerts(&exec, &scope, &[honest]).await?, 1);
    Ok(())
}


#[test]
fn a_summary_built_from_json_with_nul_is_escaped_and_accepted() -> TestResult {
    let summary = summarise(&json!({"k\u{0}": "v\u{0}"}));
    assert!(!summary.text.contains('\u{0}'));
    check_alert(
        &tenant_scope("acme")?,
        &Alert {
            summary,
            ..alert("acme", "r1", &["e1"], BASE_TIME)
        },
    )?;
    Ok(())
}


#[test]
fn the_insert_statement_writes_only_the_bound_tenant() -> TestResult {
    assert!(INSERT_SQL.contains("SELECT $1::text, id"));
    assert!(INSERT_SQL.contains("ON CONFLICT (tenant, id)"));
    Ok(())
}
