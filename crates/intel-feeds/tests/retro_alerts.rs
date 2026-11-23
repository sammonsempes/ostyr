#[path = "common/types.rs"]
mod types;


use alerts::error::StoreError;
use alerts::model::Severity;
use alerts::store::{insert_alerts, MAX_ALERTS_PER_INSERT};
use alerts::types::RowFuture;
use core_pg::scope::{tenant_scope, TenantScope};
use intel_feeds::config::ClickhouseConfig;
use intel_feeds::retro::{Direction, MatchGroup, RetroRun, RetroSettings, RetroSummary};
use intel_feeds::retro_alerts::{
    alert_of, build_alerts, escaped_host, event_id_of, micros_of, store_run, truncated_alert, AlertsError, BuildError, RETRO_RULE_ID, RETRO_TITLE,
    TRUNCATED_RULE_ID, TRUNCATED_TITLE,
};
use serde_json::json;
use std::collections::BTreeSet;
use std::sync::Mutex;
use time::macros::{date, datetime};
use time::{Date, OffsetDateTime};
use types::TestResult;


const FIRST: OffsetDateTime = datetime!(2026-11-03 01:00:00 UTC);


const LAST: OffsetDateTime = datetime!(2026-11-03 02:00:00 UTC);


const NOW: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const NOW_MICROS: u64 = 1_793_707_200_000_000;


const DAY: Date = date!(2026 - 11 - 03);


const NEXT_DAY: Date = date!(2026 - 11 - 04);


const WINDOW_START: OffsetDateTime = datetime!(2026-11-03 00:00:00 UTC);


const LATER_START: OffsetDateTime = datetime!(2026-11-03 20:00:00 UTC);


const NEXT_DAY_START: OffsetDateTime = datetime!(2026-11-04 00:00:00 UTC);


const OFFSET_START: OffsetDateTime = datetime!(2026-11-04 01:00:00 +02:00);


const BEYOND: OffsetDateTime = datetime!(+9999-12-31 23:00:00 -02:00);


const LOCAL_NEGATIVE: OffsetDateTime = datetime!(-0001-12-31 23:00:00 -01:00);


const NEGATIVE: OffsetDateTime = datetime!(-0001-06-01 00:00:00 UTC);


const BEFORE_EPOCH: OffsetDateTime = datetime!(1960-01-01 00:00:00 UTC);


const DICTIONARY_PORT: u16 = 9440;


const TIMEOUT_MS: u64 = 5_000;


const EXEC_SECONDS: u32 = 30;


const READ_ROWS: u64 = 1_000_000;


const GROUP_ROWS: u64 = 10_000;


const HASH_HEX: usize = 64;


const KEY_VARIANTS: usize = 7;


const BYTE_VALUES: usize = 256;


const HOST_LIMIT: usize = 256;


const TEN_KIB: usize = 10_240;


const GROUPS: usize = 499;


const PAIR: usize = 2;


const THREE: u32 = 3;


fn group(indicator: &str, host: &str) -> MatchGroup {
    MatchGroup {
        tenant: "tenant-a".to_owned(),
        indicator: indicator.to_owned(),
        feed: "feed-one".to_owned(),
        tlp: "amber".to_owned(),
        matched_ip: "::ffff:203.0.113.9".to_owned(),
        direction: Direction::Source,
        host: host.to_owned(),
        host_cut: false,
        event_day: DAY,
        matches: THREE,
        first_time: FIRST,
        last_time: LAST,
    }
}


fn summary(groups: usize, truncated: bool) -> RetroSummary {
    RetroSummary {
        tenant: "tenant-a".to_owned(),
        window_start: WINDOW_START,
        window_end: NOW,
        groups,
        more_than: truncated.then_some(groups),
        truncated,
        not_an_ip: 0,
        gap: None,
    }
}


fn run_of(groups: Vec<MatchGroup>, truncated: bool) -> RetroRun {
    RetroRun {
        summary: summary(groups.len(), truncated),
        groups,
    }
}


fn settings() -> RetroSettings {
    RetroSettings {
        reader: ClickhouseConfig {
            url: "http://127.0.0.1:8123".to_owned(),
            user: "retro_reader".to_owned(),
            password_file: "/nonexistent/password".into(),
            ca_file: None,
            database: "ostyr".to_owned(),
            table: "iocs".to_owned(),
            dictionary: "ioc_trie".to_owned(),
            dictionary_user: "ostyr_dict".to_owned(),
            dictionary_port: DICTIONARY_PORT,
            timeout_ms: TIMEOUT_MS,
            tenant: "tenant-a".to_owned(),
        },
        events_database: "ostyr".to_owned(),
        events_table: "events".to_owned(),
        max_matches: GROUPS,
        max_execution_seconds: EXEC_SECONDS,
        max_rows_to_read: READ_ROWS,
        max_rows_to_group_by: GROUP_ROWS,
    }
}


fn scope() -> Result<TenantScope, Box<dyn std::error::Error>> {
    Ok(tenant_scope("tenant-a")?)
}


struct Store {
    known: Mutex<BTreeSet<String>>,
    calls: Mutex<usize>,
}


fn new_store() -> Store {
    Store {
        known: Mutex::new(BTreeSet::new()),
        calls: Mutex::new(0),
    }
}


fn insert_into(store: &Store, scope: &TenantScope, batch: &[alerts::model::Alert]) -> Result<usize, StoreError> {
    let runtime = tokio::runtime::Builder::new_current_thread().build().map_err(|_| StoreError::Busy)?;
    let exec = |_scope: TenantScope, _sql: &'static str, params: Vec<String>| -> RowFuture<'_> {
        let document = params.first().cloned().ok_or(core_pg::error::PgError::InvalidTenant);
        Box::pin(async move {
            let docs: Vec<serde_json::Value> = serde_json::from_str(&document?).map_err(|_| core_pg::error::PgError::InvalidTenant)?;
            let mut known = store.known.lock().map_err(|_| core_pg::error::PgError::InvalidTenant)?;
            let fresh = docs
                .iter()
                .filter(|doc| doc.get("id").and_then(|id| id.as_str()).is_some_and(|id| known.insert(id.to_owned())))
                .count();
            *store.calls.lock().map_err(|_| core_pg::error::PgError::InvalidTenant)? += 1;
            Ok(vec![vec![fresh.to_string()]])
        })
    };
    runtime.block_on(insert_alerts(&exec, scope, batch))
}


#[test]
fn a_group_becomes_one_alert_with_fixed_title_and_the_content_in_the_summary() -> TestResult {
    let alert = alert_of(&group("203.0.113.0/24", "web-1"), NOW_MICROS)?;
    assert_eq!(alert.rule_id, RETRO_RULE_ID);
    assert_eq!(alert.rule_title, RETRO_TITLE);
    assert_eq!(alert.severity, Severity::Medium);
    assert_eq!(alert.event_time, "2026-11-03T01:00:00Z");
    assert_eq!(alert.created_micros, NOW_MICROS);
    assert_eq!(alert.host_name.as_deref(), Some("web-1"));
    assert_eq!(alert.user_name, None);
    assert!(!alert.rule_title.contains("203.0.113"));
    let value: serde_json::Value = serde_json::from_str(&alert.summary.text)?;
    assert_eq!(value.get("indicator"), Some(&json!("203.0.113.0/24")));
    assert_eq!(value.get("feed"), Some(&json!("feed-one")));
    assert_eq!(value.get("tlp"), Some(&json!("amber")));
    assert_eq!(value.get("matches"), Some(&json!(THREE)));
    assert_eq!(value.get("last_time"), Some(&json!("2026-11-03T02:00:00Z")));
    assert_eq!(value.get("host_cut"), Some(&json!(false)));
    assert_eq!(alert.event_ids, vec![event_id_of(&group("203.0.113.0/24", "web-1"))]);
    assert!(alert
        .event_ids
        .iter()
        .all(|id| id.starts_with("retro:") && id.len() == "retro:".len() + HASH_HEX));
    Ok(())
}


#[test]
fn the_event_id_depends_on_every_key_part_and_not_on_the_counts() -> TestResult {
    let base = group("203.0.113.0/24", "web-1");
    let mut counted = base.clone();
    counted.matches = THREE + 1;
    counted.last_time = NOW;
    assert_eq!(event_id_of(&base), event_id_of(&counted));
    let mut other_direction = base.clone();
    other_direction.direction = Direction::Destination;
    let mut other_ip = base.clone();
    other_ip.matched_ip = "::ffff:203.0.113.10".to_owned();
    let mut other_day = base.clone();
    other_day.event_day = NEXT_DAY;
    let mut other_tenant = base.clone();
    other_tenant.tenant = "tenant-b".to_owned();
    let ids: BTreeSet<String> = [
        &base,
        &other_direction,
        &other_ip,
        &other_day,
        &other_tenant,
        &group("198.51.100.0/24", "web-1"),
        &group("203.0.113.0/24", "web-2"),
    ]
    .into_iter()
    .map(event_id_of)
    .collect();
    assert_eq!(ids.len(), KEY_VARIANTS);
    Ok(())
}


#[test]
fn the_host_is_escaped_and_cut_on_an_escape_boundary() -> TestResult {
    assert_eq!(escaped_host("web-1"), ("web-1".to_owned(), false));
    assert_eq!(escaped_host("a\u{0}b\\"), ("a\\u{0}b\\u{5c}".to_owned(), false));
    let (cut, was_cut) = escaped_host(&"\u{202e}".repeat(TEN_KIB));
    assert!(was_cut);
    assert!(cut.chars().count() <= HOST_LIMIT);
    assert!(cut.chars().count() > HOST_LIMIT - "\\u{202e}".len());
    assert!(cut.ends_with('}'));
    let (long, long_cut) = escaped_host(&"a".repeat(TEN_KIB));
    assert_eq!((long.len(), long_cut), (HOST_LIMIT, true));
    Ok(())
}


#[test]
fn a_nul_host_is_kept_escaped_and_an_empty_host_is_none() -> TestResult {
    let nul = alert_of(&group("203.0.113.0/24", "a\u{0}b"), NOW_MICROS)?;
    assert_eq!(nul.host_name.as_deref(), Some("a\\u{0}b"));
    assert_eq!(alert_of(&group("203.0.113.0/24", ""), NOW_MICROS)?.host_name, None);
    let mut cut = group("203.0.113.0/24", "web-1");
    cut.host_cut = true;
    let value: serde_json::Value = serde_json::from_str(&alert_of(&cut, NOW_MICROS)?.summary.text)?;
    assert_eq!(value.get("host_cut"), Some(&json!(true)));
    let long = alert_of(&group("203.0.113.0/24", &"\u{202e}".repeat(TEN_KIB)), NOW_MICROS)?;
    let long_value: serde_json::Value = serde_json::from_str(&long.summary.text)?;
    assert_eq!(long_value.get("host_cut"), Some(&json!(true)));
    Ok(())
}


#[test]
fn a_time_that_rfc3339_cannot_write_is_a_build_error() -> TestResult {
    let mut late_first = group("203.0.113.0/24", "web-1");
    late_first.first_time = NEGATIVE;
    assert!(matches!(alert_of(&late_first, NOW_MICROS), Err(BuildError::Time(_))));
    let mut late_last = group("203.0.113.0/24", "web-1");
    late_last.last_time = NEGATIVE;
    assert!(matches!(alert_of(&late_last, NOW_MICROS), Err(BuildError::Time(_))));
    assert!(BuildError::Range.to_string().contains("UTC range"));
    Ok(())
}


#[test]
fn the_truncation_alert_is_one_per_utc_day_of_the_window_start() -> TestResult {
    let first = truncated_alert(&summary(GROUPS, true), NOW_MICROS)?;
    let mut later = summary(GROUPS, true);
    later.window_start = LATER_START;
    let second = truncated_alert(&later, NOW_MICROS)?;
    assert_eq!(first.id, second.id);
    assert_eq!(first.event_ids, vec!["retro-truncated:2026-11-03".to_owned()]);
    assert_eq!(first.rule_id, TRUNCATED_RULE_ID);
    assert_eq!(first.rule_title, TRUNCATED_TITLE);
    let mut next_day = summary(GROUPS, true);
    next_day.window_start = NEXT_DAY_START;
    assert_ne!(truncated_alert(&next_day, NOW_MICROS)?.id, first.id);
    let mut offset = summary(GROUPS, true);
    offset.window_start = OFFSET_START;
    assert_eq!(truncated_alert(&offset, NOW_MICROS)?.event_ids, first.event_ids);
    let value: serde_json::Value = serde_json::from_str(&first.summary.text)?;
    assert_eq!(value.get("more_than"), Some(&json!(GROUPS)));
    Ok(())
}


#[test]
fn the_truncation_alert_refuses_times_outside_the_range() -> TestResult {
    let mut beyond = summary(GROUPS, true);
    beyond.window_start = BEYOND;
    assert!(matches!(truncated_alert(&beyond, NOW_MICROS), Err(BuildError::Range)));
    let mut negative = summary(GROUPS, true);
    negative.window_start = NEGATIVE;
    assert!(matches!(truncated_alert(&negative, NOW_MICROS), Err(BuildError::Time(_))));
    let mut local = summary(GROUPS, true);
    local.window_start = LOCAL_NEGATIVE;
    assert!(matches!(truncated_alert(&local, NOW_MICROS), Err(BuildError::Time(_))));
    let mut end = summary(GROUPS, true);
    end.window_end = NEGATIVE;
    assert!(matches!(truncated_alert(&end, NOW_MICROS), Err(BuildError::Time(_))));
    Ok(())
}


#[test]
fn a_refused_alert_is_skipped_and_counted_and_the_rest_are_kept() -> TestResult {
    let mut bad = group("203.0.113.0/24", "web-1");
    bad.first_time = NEGATIVE;
    let mut foreign = group("198.51.100.0/24", "web-1");
    foreign.tenant = "tenant-b".to_owned();
    let run = run_of(vec![bad, foreign, group("192.0.2.0/24", "web-1")], false);
    let built = build_alerts(&scope()?, &run, NOW_MICROS);
    assert_eq!((built.alerts.len(), built.refused), (1, PAIR));
    Ok(())
}


#[test]
fn a_truncated_run_adds_the_truncation_alert_and_never_exceeds_one_insert() -> TestResult {
    let groups: Vec<MatchGroup> = (0..GROUPS)
        .map(|index| group(&format!("10.{}.{}.0/24", index / BYTE_VALUES, index % BYTE_VALUES), "web-1"))
        .collect();
    let run = run_of(groups, true);
    let built = build_alerts(&scope()?, &run, NOW_MICROS);
    assert_eq!((built.alerts.len(), built.refused), (GROUPS + 1, 0));
    assert!(built.alerts.len() <= MAX_ALERTS_PER_INSERT);
    assert!(built.alerts.iter().any(|alert| alert.rule_id == TRUNCATED_RULE_ID));
    let store = new_store();
    let report = store_run(&settings(), &run, NOW, &|scope, batch| insert_into(&store, scope, batch))?;
    assert_eq!(
        (report.built, report.inserted, report.known, report.truncated_alert),
        (GROUPS + 1, GROUPS + 1, 0, true)
    );
    Ok(())
}


#[test]
fn a_refused_truncation_alert_is_counted_and_the_groups_still_insert() -> TestResult {
    let mut run = run_of(vec![group("192.0.2.0/24", "web-1")], true);
    run.summary.window_start = BEYOND;
    let built = build_alerts(&scope()?, &run, NOW_MICROS);
    assert_eq!((built.alerts.len(), built.refused), (1, 1));
    Ok(())
}


#[test]
fn a_rerun_on_the_same_window_inserts_nothing_new_and_a_duplicate_id_is_merged() -> TestResult {
    let mut again = group("203.0.113.0/24", "web-1");
    again.host_cut = true;
    let run = run_of(vec![group("203.0.113.0/24", "web-1"), again, group("192.0.2.0/24", "web-2")], false);
    let store = new_store();
    let insert = |scope: &TenantScope, batch: &[alerts::model::Alert]| insert_into(&store, scope, batch);
    let first = store_run(&settings(), &run, NOW, &insert)?;
    assert_eq!((first.built, first.inserted, first.known, first.refused), (PAIR, PAIR, 0, 0));
    let second = store_run(&settings(), &run, NOW, &insert)?;
    assert_eq!((second.built, second.inserted, second.known), (PAIR, 0, PAIR));
    assert_eq!(*store.calls.lock().map_err(|_| "poisoned")?, PAIR);
    let mut larger = run.clone();
    larger.groups.iter_mut().for_each(|found| found.matches = THREE * PAIR as u32);
    assert_eq!(store_run(&settings(), &larger, NOW, &insert)?.inserted, 0);
    Ok(())
}


#[test]
fn an_empty_run_still_makes_one_insert_call_of_nothing() -> TestResult {
    let store = new_store();
    let report = store_run(&settings(), &run_of(Vec::new(), false), NOW, &|scope, batch| {
        insert_into(&store, scope, batch)
    })?;
    assert_eq!((report.built, report.inserted, report.known, report.truncated_alert), (0, 0, 0, false));
    Ok(())
}


#[test]
fn the_store_refuses_a_run_for_another_tenant_scope_and_errors_are_typed() -> TestResult {
    let run = run_of(vec![group("203.0.113.0/24", "web-1")], false);
    let mut bad_tenant = settings();
    bad_tenant.reader.tenant = "-x".to_owned();
    assert!(matches!(store_run(&bad_tenant, &run, NOW, &|_, _| Ok(0)), Err(AlertsError::Tenant(_))));
    let mut other = settings();
    other.reader.tenant = "tenant-b".to_owned();
    let report = store_run(&other, &run, NOW, &|_, batch| Ok(batch.len()))?;
    assert_eq!((report.built, report.refused), (0, 1));
    assert!(matches!(
        store_run(&settings(), &run, BEFORE_EPOCH, &|_, _| Ok(0)),
        Err(AlertsError::Clock)
    ));
    assert!(matches!(
        store_run(&settings(), &run, NOW, &|_, _| Err(StoreError::Busy)),
        Err(AlertsError::Insert(StoreError::Busy))
    ));
    assert_eq!(micros_of(NOW)?, NOW_MICROS);
    Ok(())
}
