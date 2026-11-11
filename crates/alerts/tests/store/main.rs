mod memory;
mod types;


use alerts::error::StoreError;
use alerts::id::{alert_id, is_alert_id, ID_HEX_LENGTH};
use alerts::model::{Alert, Cursor, Page, Severity, Summary, TriageChange, TriageStatus, SEVERITY_COLUMN};
use alerts::store::{
    check_alert, check_page, format_cursor, get_alert, get_triage, insert_alerts, list_alerts, parse_cursor, set_triage, summarise, CREATED_COLUMN,
    EVENT_IDS_COLUMN, FIRST_SQL, GET_SQL, INSERT_SQL, MAX_ALERTS_PER_INSERT, MAX_CREATED_MICROS, MAX_ENTITY_CHARS, MAX_EVENT_IDS, MAX_EVENT_ID_CHARS,
    MAX_EVENT_TIME_CHARS, MAX_NOTE_CHARS, MAX_PAGE_SIZE, MAX_RULE_ID_CHARS, MAX_SUMMARY_BYTES, MAX_TITLE_CHARS, MIGRATIONS, MIGRATION_NAMESPACE,
    NEXT_SQL, ORIGINAL_BYTES_COLUMN, TRIAGE_GET_SQL, TRIAGE_INSERT_SQL, TRIAGE_UPDATE_SQL, TRUNCATED_COLUMN,
};
use alerts::types::{Row, RowFuture};
use core_pg::error::PgError;
use core_pg::migrate::{check_embedded, check_namespace};
use core_pg::scope::{tenant_scope, TenantScope};
use memory::{handle, lock, row_of, Db, Forced};
use serde_json::json;
use std::future::ready;
use types::{Mutation, TestResult};


const KNOWN_ID: &str = "2d6c7e2fdf972aab0077338ff3c04044ccb108f41661aa365bea425f0b894fee";


const TWO: usize = 2;


const THREE: usize = 3;


const FOUR: usize = 4;


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
    assert!(MIGRATIONS
        .iter()
        .take(TWO)
        .all(|migration| migration.sql.contains("PRIMARY KEY (tenant, id)")));
    assert!(INSERT_SQL.contains("ON CONFLICT (tenant, id) DO NOTHING"));
    assert!(INSERT_SQL.contains("queued AS (") && INSERT_SQL.contains("INSERT INTO alert_outbox (tenant, id) SELECT $1::text, id FROM written"));
    let outbox = MIGRATIONS.get(1).ok_or("no migration")?;
    let queued = MIGRATIONS.get(TWO).ok_or("no migration")?;
    assert!(queued.sql.contains("ADD COLUMN queued_at timestamptz NOT NULL DEFAULT now()") && queued.sql.contains("(tenant, queued_at)"));
    assert!(
        outbox.sql.contains("CREATE INDEX alert_outbox_by_seq ON alert_outbox (tenant, seq)") && outbox.sql.contains("GENERATED ALWAYS AS IDENTITY")
    );
    assert!(outbox.sql.contains("INSERT INTO alert_outbox (tenant, id) SELECT tenant, id FROM alerts"));
    [FIRST_SQL, NEXT_SQL, GET_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("WHERE tenant = $1")));
    assert_eq!(MIGRATIONS.len(), FOUR);
    let triage = MIGRATIONS.get(THREE).ok_or("no migration")?;
    assert!(triage.sql.contains("PRIMARY KEY (tenant, alert_id)") && triage.sql.contains("REFERENCES alerts (tenant, id) ON DELETE CASCADE"));
    assert!(triage.sql.contains("CHECK (status IN ('acknowledged', 'closed'))"));
    [TRIAGE_INSERT_SQL, TRIAGE_UPDATE_SQL]
        .iter()
        .for_each(|sql| assert!(sql.contains("tenant = $1") && sql.contains("FROM alerts WHERE tenant = $1 AND id = $2::text")));
    assert!(TRIAGE_UPDATE_SQL.contains("AND version = $7::text::bigint") && TRIAGE_UPDATE_SQL.contains("version = version + 1"));
    assert!(TRIAGE_INSERT_SQL.contains("ON CONFLICT (tenant, alert_id) DO NOTHING"));
    assert!(TRIAGE_GET_SQL.contains("WHERE tenant = $1"));
    Ok(())
}


pub fn change(status: TriageStatus, actor: &str, note: Option<&str>) -> TriageChange {
    TriageChange {
        status,
        actor: actor.to_owned(),
        note: note.map(str::to_owned),
        now: BASE_TIME,
    }
}


#[tokio::test]
async fn triage_inserts_then_updates_with_the_right_version() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let one = alert("acme", "r1", &["e1"], BASE_TIME);
    insert_alerts(&exec, &scope, std::slice::from_ref(&one)).await?;
    assert_eq!(get_triage(&exec, &scope, &one.id).await?, None);
    let first = set_triage(&exec, &scope, &one.id, &change(TriageStatus::Acknowledged, "ana", Some("looking")), None).await?;
    assert_eq!(
        (first.version, first.status, first.note.as_deref()),
        (1, TriageStatus::Acknowledged, Some("looking"))
    );
    let second = set_triage(&exec, &scope, &one.id, &change(TriageStatus::Closed, "bob", None), Some(1)).await?;
    assert_eq!(
        (second.version, second.status, second.note.as_deref(), second.updated_at),
        (TWO as i64, TriageStatus::Closed, None, BASE_TIME)
    );
    assert_eq!(get_triage(&exec, &scope, &one.id).await?, Some(second));
    Ok(())
}


#[tokio::test]
async fn a_stale_version_or_a_second_insert_is_a_conflict_and_changes_nothing() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let one = alert("acme", "r1", &["e1"], BASE_TIME);
    insert_alerts(&exec, &scope, std::slice::from_ref(&one)).await?;
    let first = set_triage(&exec, &scope, &one.id, &change(TriageStatus::Acknowledged, "ana", None), None).await?;
    let again = set_triage(&exec, &scope, &one.id, &change(TriageStatus::Closed, "eve", None), None).await;
    assert!(matches!(again, Err(StoreError::Conflict)));
    let stale = set_triage(&exec, &scope, &one.id, &change(TriageStatus::Closed, "eve", None), Some(TWO as i64)).await;
    assert!(matches!(stale, Err(StoreError::Conflict)));
    assert_eq!(get_triage(&exec, &scope, &one.id).await?, Some(first));
    let missing_row = alert("acme", "r2", &["e2"], BASE_TIME);
    insert_alerts(&exec, &scope, std::slice::from_ref(&missing_row)).await?;
    let none_yet = set_triage(&exec, &scope, &missing_row.id, &change(TriageStatus::Closed, "eve", None), Some(1)).await;
    assert!(matches!(none_yet, Err(StoreError::Conflict)));
    assert_eq!(get_triage(&exec, &scope, &missing_row.id).await?, None);
    Ok(())
}


#[tokio::test]
async fn another_tenants_alert_or_an_unknown_alert_is_not_found_and_writes_nothing() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope_a = tenant_scope("a")?;
    let scope_b = tenant_scope("b")?;
    let theirs = alert("b", "r1", &["e1"], BASE_TIME);
    insert_alerts(&exec, &scope_b, std::slice::from_ref(&theirs)).await?;
    for expected in [None, Some(1)] {
        let result = set_triage(&exec, &scope_a, &theirs.id, &change(TriageStatus::Closed, "eve", None), expected).await;
        assert!(matches!(result, Err(StoreError::NotFound)));
    }
    assert!(lock(&db.triage).is_empty());
    assert_eq!(get_triage(&exec, &scope_a, &theirs.id).await?, None);
    set_triage(&exec, &scope_b, &theirs.id, &change(TriageStatus::Closed, "bob", None), None).await?;
    assert_eq!(get_triage(&exec, &scope_a, &theirs.id).await?, None);
    assert!(get_triage(&exec, &scope_b, &theirs.id).await?.is_some());
    Ok(())
}


#[tokio::test]
async fn triage_bounds_are_refused_before_any_statement() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let one = alert("acme", "r1", &["e1"], BASE_TIME);
    insert_alerts(&exec, &scope, std::slice::from_ref(&one)).await?;
    let before = sent(&db);
    let long_actor = "a".repeat(MAX_ENTITY_CHARS + 1);
    let long_note = "n".repeat(MAX_NOTE_CHARS + 1);
    let mut late = change(TriageStatus::Closed, "ana", None);
    late.now = MAX_CREATED_MICROS + 1;
    let refused = [
        (one.id.as_str(), change(TriageStatus::Closed, "", None)),
        (one.id.as_str(), change(TriageStatus::Closed, &long_actor, None)),
        (one.id.as_str(), change(TriageStatus::Closed, "a\0b", None)),
        (one.id.as_str(), change(TriageStatus::Closed, "ana", Some(&long_note))),
        (one.id.as_str(), change(TriageStatus::Closed, "ana", Some("x\0y"))),
        (one.id.as_str(), change(TriageStatus::Closed, "ana", Some(""))),
        (one.id.as_str(), late),
        ("not-an-id", change(TriageStatus::Closed, "ana", None)),
    ];
    for (id, request) in &refused {
        assert!(set_triage(&exec, &scope, id, request, None).await.is_err());
        assert!(set_triage(&exec, &scope, id, request, Some(1)).await.is_err());
    }
    assert!(matches!(get_triage(&exec, &scope, "not-an-id").await, Err(StoreError::BadId)));
    assert_eq!(sent(&db), before);
    let boundary = change(TriageStatus::Closed, &"a".repeat(MAX_ENTITY_CHARS), Some(&"n".repeat(MAX_NOTE_CHARS)));
    assert!(set_triage(&exec, &scope, &one.id, &boundary, None).await.is_ok());
    Ok(())
}


#[tokio::test]
async fn triage_store_failures_are_typed() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let one = alert("acme", "r1", &["e1"], BASE_TIME);
    let request = change(TriageStatus::Closed, "ana", None);
    lock(&db.forced).push_back(Forced::Fail);
    assert!(matches!(set_triage(&exec, &scope, &one.id, &request, None).await, Err(StoreError::Pg(_))));
    let answers: Vec<Vec<Row>> = vec![
        Vec::new(),
        vec![vec!["many".to_owned(), "1".to_owned()]],
        vec![vec!["1".to_owned()]],
        vec![vec!["1".to_owned(), "9223372036854775808".to_owned()]],
        vec![vec!["1".to_owned(), "x".to_owned()]],
    ];
    for rows in answers {
        lock(&db.forced).push_back(Forced::Rows(rows));
        assert!(set_triage(&exec, &scope, &one.id, &request, None).await.is_err());
    }
    lock(&db.forced).push_back(Forced::Fail);
    assert!(matches!(get_triage(&exec, &scope, &one.id).await, Err(StoreError::Pg(_))));
    let good = vec!["closed".to_owned(), "ana".to_owned(), String::new(), "5".to_owned(), "1".to_owned()];
    let damaged_rows: Vec<Row> = [0, THREE, FOUR]
        .into_iter()
        .map(|column| {
            let mut row = good.clone();
            row.splice(column..=column, ["bad".to_owned()]);
            row
        })
        .chain(std::iter::once(good.iter().take(TWO).cloned().collect()))
        .collect();
    for row in damaged_rows {
        lock(&db.forced).push_back(Forced::Rows(vec![row]));
        assert!(get_triage(&exec, &scope, &one.id).await.is_err());
    }
    lock(&db.forced).push_back(Forced::Rows(vec![good]));
    assert!(get_triage(&exec, &scope, &one.id).await?.is_some());
    Ok(())
}


#[test]
fn triage_status_text_round_trips() -> TestResult {
    [TriageStatus::Acknowledged, TriageStatus::Closed]
        .iter()
        .try_for_each(|status| status.to_string().parse::<TriageStatus>().map(|parsed| assert_eq!(parsed, *status)))?;
    assert!("new".parse::<TriageStatus>().is_err());
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
        Box::new(|candidate| {
            candidate.summary.truncated = true;
            candidate.summary.original_bytes = u64::MAX;
        }),
    ];
    let failures = cases
        .iter()
        .map(|mutate| refused(&scope, mutate))
        .collect::<Result<Vec<StoreError>, _>>()?;
    assert!(matches!(failures.first(), Some(StoreError::TenantMismatch)));
    assert!(matches!(failures.get(1), Some(StoreError::FieldEmpty { field: "rule_id" })));
    assert!(matches!(failures.get(TWO), Some(StoreError::FieldTooLong { field: "rule_id", .. })));
    assert!(matches!(failures.last(), Some(StoreError::BadOriginalBytes)));
    assert!(failures.iter().any(|failure| matches!(failure, StoreError::IdMismatch)));
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
        format!("+5.{KNOWN_ID}"),
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


#[tokio::test]
async fn a_huge_original_size_is_refused_before_any_sql_and_the_honest_alert_stores_alone() -> TestResult {
    let db = Db::default();
    let exec = executor(&db);
    let scope = tenant_scope("acme")?;
    let mut hostile = alert("acme", "ok2", &["e1"], BASE_TIME);
    hostile.summary.truncated = true;
    hostile.summary.original_bytes = u64::MAX;
    let honest = alert("acme", "ok", &["e1"], BASE_TIME);
    let error = insert_alerts(&exec, &scope, &[honest.clone(), hostile]).await.err().ok_or("accepted")?;
    assert!(matches!(error, StoreError::BadOriginalBytes));
    assert_eq!(sent(&db), 0);
    assert_eq!(insert_alerts(&exec, &scope, &[honest]).await?, 1);
    Ok(())
}


#[test]
fn the_length_is_checked_before_the_nul_scan() -> TestResult {
    let long_with_nul = format!("{}\u{0}", "r".repeat(MAX_RULE_ID_CHARS + 1));
    let error = refused(&tenant_scope("acme")?, |candidate| candidate.rule_id = long_with_nul.clone())?;
    assert!(matches!(error, StoreError::FieldTooLong { field: "rule_id", .. }));
    Ok(())
}


#[test]
fn both_list_statements_order_by_the_table_columns() -> TestResult {
    [FIRST_SQL, NEXT_SQL].iter().try_for_each(|sql| -> TestResult {
        assert!(sql.contains("ORDER BY alerts.created DESC, alerts.id DESC LIMIT"), "{sql}");
        let output = sql.split(" FROM ").next().ok_or("no select list")?;
        assert!(!output.contains(" AS created") && !output.contains(" AS id"), "{sql}");
        assert!(output.contains("created::text,"));
        assert!(
            output.split("::text").skip(1).all(|rest| rest.is_empty() || rest.starts_with(',')),
            "{sql}"
        );
        Ok(())
    })
}


#[test]
fn the_memory_store_refuses_a_document_with_missing_fields() -> TestResult {
    let db = Db::default();
    let scope = tenant_scope("acme")?;
    let error = handle(&db, &scope, INSERT_SQL, &["[{\"id\":\"x\"}]".to_owned()])
        .err()
        .ok_or("accepted")?;
    assert!(matches!(error, PgError::Server { .. }));
    let full = json!({
        "id": "x", "rule_id": "r", "rule_title": "t", "severity": "low", "event_time": "now", "created": 1, "host_name": null,
        "user_name": "u", "event_ids": ["e"], "summary": "{}", "summary_truncated": false, "summary_original_bytes": 1
    });
    assert!(row_of(&full).is_ok());
    [
        "id",
        "rule_id",
        "rule_title",
        "severity",
        "event_time",
        "host_name",
        "user_name",
        "event_ids",
        "summary",
    ]
    .iter()
    .try_for_each(|field| -> TestResult {
        let mut broken = full.clone();
        broken.as_object_mut().ok_or("not an object")?.remove(*field);
        assert!(row_of(&broken).is_err(), "{field}");
        Ok(())
    })?;
    let mut wrong_type = full.clone();
    wrong_type.as_object_mut().ok_or("not an object")?.insert("id".to_owned(), json!(true));
    assert!(row_of(&wrong_type).is_err());
    Ok(())
}
