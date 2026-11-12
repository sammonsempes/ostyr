#[path = "common/types.rs"]
mod types;


use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{MAX_CREATED_MICROS, MAX_TITLE_CHARS};
use alerts::types::{Executor, RowFuture};
use core_export::ecs::{EndpointFields, HostFields};
use core_pg::error::PgError;
use core_pg::migrate::{check_embedded, check_namespace};
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use dhcp_kea::alerting::{
    advance_cursor, alerted_in_batch, alerted_macs, candidate_macs, day_of, flood_alert, mac_of, micros_of, next_chunk_of, peer_fields,
    store_unknown_device_alerts, unknown_device_alerts, unknown_device_alerts_in_order, Lookup, ALERTED_SQL, FLOOD_RULE_ID, MAX_LOOKUP_CHUNKS,
    MAX_LOOKUP_MACS, MAX_UNKNOWN_PER_RUN, MICROS_PER_SECOND, SECONDS_PER_DAY, UNKNOWN_RULE_ID,
};
use dhcp_kea::cursor::{read_cursor, write_cursor, MIGRATIONS, MIGRATION_NAMESPACE, READ_SQL as CURSOR_READ_SQL, WRITE_SQL as CURSOR_WRITE_SQL};
use dhcp_kea::header::parse_header;
use dhcp_kea::row::{convert_row, Converted};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::future::ready;
use std::io::{Read, Seek, SeekFrom};
use std::sync::{Arc, LazyLock, Mutex};
use types::TestResult;


const HEADER: &str = "address,hwaddr,client_id,valid_lifetime,expire,subnet_id,fqdn_fwd,fqdn_rev,hostname,state,user_context";


const NOW_MICROS: u64 = 1_700_000_000_000_000;


const CLTT: i64 = 1_700_000_000;


const LIFETIME: i64 = 3_600;


const EXPIRE: i64 = CLTT + LIFETIME;


const DOUBLE_LIFETIME: i64 = 7_200;


const EXPIRE_LATER: i64 = CLTT + DOUBLE_LIFETIME;


const EXPIRE_RENEWED: i64 = CLTT + 9_000;


const TOO_LONG_HOSTNAME: usize = 300;


const FLOOD_MACS: usize = 450;


const BAD_KNOWN: usize = 2;


const EXTRA: usize = 3;


const TWO_CHUNKS: usize = 2;


const THREE_CHUNKS: usize = 3;


const FOUR_CHUNKS: usize = 4;


const FIVE_CHUNKS: usize = 5;


const STORED_CURSOR: usize = 7;


const HOSTILE_BYTES: usize = 4_096;


const OCTET_RANGE: usize = 256;


const SUMMARY_LIMIT: usize = 512;


#[derive(Default)]
pub struct Store {
    pub rows: Mutex<BTreeSet<(String, String)>>,
    pub fail: bool,
    pub fail_lookup: bool,
    pub fail_from_lookup: Option<usize>,
    pub lookups: Mutex<usize>,
    pub cursors: Mutex<BTreeMap<String, String>>,
    pub fail_cursor_read: bool,
    pub fail_cursor_write: bool,
}


pub fn cursor_statement(store: &Store, scope: &TenantScope, sql: &str, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let mut cursors = store.cursors.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let tenant = tenant_of(scope).to_owned();
    if sql == CURSOR_READ_SQL {
        Ok(cursors.get(&tenant).map_or_else(Vec::new, |text| vec![vec![text.clone()]]))
    } else {
        let next = params.first().cloned().ok_or(PgError::InvalidTenant)?;
        cursors.insert(tenant, next.clone());
        Ok(vec![vec![next]])
    }
}


pub fn run(store: &Store, scope: &TenantScope, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let docs: Vec<Value> = params
        .first()
        .ok_or(PgError::InvalidTenant)
        .and_then(|text| serde_json::from_str(text).map_err(|_bad| PgError::InvalidTenant))?;
    let mut rows = store.rows.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let tenant = tenant_of(scope).to_owned();
    let new = docs
        .iter()
        .filter_map(|doc| doc.get("id").and_then(Value::as_str))
        .filter(|id| rows.insert((tenant.clone(), (*id).to_owned())))
        .count();
    Ok(vec![vec![new.to_string()]])
}


pub fn lookup(store: &Store, scope: &TenantScope, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let ids: Vec<String> = params
        .first()
        .ok_or(PgError::InvalidTenant)
        .and_then(|text| serde_json::from_str(text).map_err(|_bad| PgError::InvalidTenant))?;
    let mut count = store.lookups.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    *count += 1;
    let rows = store.rows.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
    let tenant = tenant_of(scope).to_owned();
    Ok(ids
        .into_iter()
        .filter(|id| rows.contains(&(tenant.clone(), id.clone())))
        .map(|id| vec![id])
        .collect())
}


pub fn lookups_so_far(store: &Store) -> usize {
    store.lookups.lock().map_or(0, |count| *count)
}


pub fn executor<'a>(store: &'a Store) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> {
        let late_failure = store.fail_from_lookup.is_some_and(|from| lookups_so_far(store) >= from);
        let cursor_failure = (store.fail_cursor_read && sql == CURSOR_READ_SQL) || (store.fail_cursor_write && sql == CURSOR_WRITE_SQL);
        if store.fail || cursor_failure || (store.fail_lookup && sql == ALERTED_SQL) || (late_failure && sql == ALERTED_SQL) {
            Box::pin(ready(Err(PgError::InvalidTenant)))
        } else if sql == CURSOR_READ_SQL || sql == CURSOR_WRITE_SQL {
            Box::pin(ready(cursor_statement(store, &scope, sql, &params)))
        } else if sql == ALERTED_SQL {
            Box::pin(ready(lookup(store, &scope, &params)))
        } else {
            Box::pin(ready(run(store, &scope, &params)))
        }
    }
}


fn lease(mac: &str, address: &str, hostname: &str, expire: i64) -> Result<Converted, Box<dyn std::error::Error>> {
    let columns = parse_header(HEADER)?;
    let row = format!("{address},{mac},,{LIFETIME},{expire},7,0,0,{hostname},0,");
    Ok(convert_row(&columns, &row)?)
}


fn known(macs: &[&str]) -> BTreeSet<String> {
    macs.iter().map(|mac| (*mac).to_owned()).collect()
}


fn mac_number(index: usize) -> String {
    format!("02:00:00:00:{:02x}:{:02x}", index / OCTET_RANGE, index % OCTET_RANGE)
}


fn many_leases(count: usize) -> Result<Vec<Converted>, Box<dyn std::error::Error>> {
    (0..count).map(|index| lease(&mac_number(index), "10.0.0.1", "", EXPIRE)).collect()
}


fn summary_of(alert: &Alert) -> Result<Value, serde_json::Error> {
    serde_json::from_str(&alert.summary.text)
}


#[test]
fn macs_are_compared_in_the_ecs_form() -> TestResult {
    let scope = tenant_scope("acme")?;
    let mut loose = lease("aa:bb:cc:dd:ee:ff", "10.0.0.4", "", EXPIRE)?;
    loose.event.source = Some(EndpointFields {
        mac: Some("aa:bb:cc:dd:ee:ff".to_owned()),
        ..EndpointFields::default()
    });
    let leases = [
        lease("aa:bb:cc:dd:ee:ff", "10.0.0.1", "", EXPIRE)?,
        lease("11:22:33:44:55:66", "10.0.0.2", "", EXPIRE)?,
        lease("AA:BB:CC:DD:EE:01", "10.0.0.3", "", EXPIRE)?,
        loose,
    ];
    let (alerts, rejected) = unknown_device_alerts(&scope, &leases, &known(&["AA-BB-CC-DD-EE-FF"]), NOW_MICROS);
    let titles: Vec<&str> = alerts.iter().map(|alert| alert.rule_title.as_str()).collect();
    assert_eq!(
        titles,
        [
            "DHCP lease for unknown device 11-22-33-44-55-66",
            "DHCP lease for unknown device AA-BB-CC-DD-EE-01"
        ]
    );
    assert_eq!((rejected.no_mac, rejected.bad_known), (0, 0));
    assert!(alerts
        .iter()
        .all(|alert| alert.rule_id == UNKNOWN_RULE_ID && alert.severity == Severity::Low && alert.tenant == "acme"));
    assert!(alerts.iter().all(|alert| alert.created_micros == NOW_MICROS));
    Ok(())
}


#[test]
fn a_known_entry_in_another_form_is_counted_and_never_matches() -> TestResult {
    let scope = tenant_scope("acme")?;
    let leases = [lease("aa:bb:cc:dd:ee:ff", "10.0.0.1", "", EXPIRE)?];
    let (alerts, rejected) = unknown_device_alerts(&scope, &leases, &known(&["aa:bb:cc:dd:ee:ff", "zz", "AA-BB-CC-DD-EE-FF"]), NOW_MICROS);
    assert_eq!((alerts.len(), rejected.bad_known), (0, BAD_KNOWN));
    let (loose, loose_rejected) = unknown_device_alerts(&scope, &leases, &known(&["aa:bb:cc:dd:ee:ff"]), NOW_MICROS);
    assert_eq!((loose.len(), loose_rejected.bad_known), (1, 1));
    Ok(())
}


#[test]
fn the_same_mac_twice_gives_one_alert_with_the_first_lease() -> TestResult {
    let scope = tenant_scope("acme")?;
    let leases = [
        lease("aa:bb:cc:dd:ee:ff", "10.0.0.1", "", EXPIRE)?,
        lease("AA-BB-CC-DD-EE-FF", "10.0.0.9", "", EXPIRE_LATER)?,
    ];
    let (alerts, _rejected) = unknown_device_alerts(&scope, &leases, &BTreeSet::new(), NOW_MICROS);
    assert_eq!(alerts.len(), 1);
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!(alert.event_time, (CLTT as u64 * MICROS_PER_SECOND).to_string());
    assert_eq!(summary_of(alert)?.get("ip").and_then(Value::as_str), Some("10.0.0.1"));
    Ok(())
}


#[tokio::test]
async fn a_renewal_with_a_new_ip_keeps_the_identity() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let first = [lease("aa:bb:cc:dd:ee:ff", "10.0.0.1", "pc1", EXPIRE)?];
    let second = [lease("aa:bb:cc:dd:ee:ff", "10.0.0.77", "pc1", EXPIRE_RENEWED)?];
    let (first_alerts, _first_rejected) = unknown_device_alerts(&scope, &first, &BTreeSet::new(), NOW_MICROS);
    let (second_alerts, _second_rejected) = unknown_device_alerts(&scope, &second, &BTreeSet::new(), NOW_MICROS + 1);
    assert_eq!(first_alerts.first().map(|alert| &alert.id), second_alerts.first().map(|alert| &alert.id));
    assert_eq!(
        first_alerts.first().map(|alert| alert.event_ids.clone()),
        Some(vec!["mac:AA-BB-CC-DD-EE-FF".to_owned()])
    );
    assert_eq!(store_unknown_device_alerts(&exec, &scope, &first_alerts).await?, 1);
    assert_eq!(store_unknown_device_alerts(&exec, &scope, &first_alerts).await?, 0);
    assert_eq!(store_unknown_device_alerts(&exec, &scope, &second_alerts).await?, 0);
    Ok(())
}


#[test]
fn a_hostile_hostname_never_reaches_the_title_or_an_unbounded_summary() -> TestResult {
    let scope = tenant_scope("acme")?;
    let hostile = format!("\u{1b}[31mevil\u{7}{}", "a".repeat(HOSTILE_BYTES));
    let from_row = lease("aa:bb:cc:dd:ee:ff", "10.0.0.1", &hostile, EXPIRE)?;
    let mut forged = lease("aa:bb:cc:dd:ee:01", "10.0.0.2", "", EXPIRE)?;
    forged.event.host = Some(HostFields {
        hostname: Some(hostile),
        ..HostFields::default()
    });
    let mut too_long = lease("aa:bb:cc:dd:ee:02", "10.0.0.3", "", EXPIRE)?;
    too_long.event.host = Some(HostFields {
        hostname: Some("a".repeat(TOO_LONG_HOSTNAME)),
        ..HostFields::default()
    });
    let (alerts, _rejected) = unknown_device_alerts(&scope, &[from_row, forged, too_long], &BTreeSet::new(), NOW_MICROS);
    assert_eq!(alerts.len(), EXTRA);
    for alert in &alerts {
        assert!(!alert.rule_title.contains('\u{1b}') && alert.rule_title.len() < MAX_TITLE_CHARS);
        assert!(!alert.summary.text.contains('\u{1b}') && alert.summary.text.len() < SUMMARY_LIMIT);
        assert_eq!(summary_of(alert)?.get("hostname"), Some(&Value::Null));
    }
    Ok(())
}


#[test]
fn a_valid_hostname_and_ip_go_to_the_summary_only() -> TestResult {
    let scope = tenant_scope("acme")?;
    let leases = [lease("aa:bb:cc:dd:ee:ff", "10.0.0.1", "pc1.example.", EXPIRE)?];
    let (alerts, _rejected) = unknown_device_alerts(&scope, &leases, &BTreeSet::new(), NOW_MICROS);
    let alert = alerts.first().ok_or("no alert")?;
    let summary = summary_of(alert)?;
    assert_eq!(summary.get("hostname").and_then(Value::as_str), Some("pc1.example"));
    assert_eq!(summary.get("ip").and_then(Value::as_str), Some("10.0.0.1"));
    assert!(!alert.rule_title.contains("pc1") && !alert.rule_title.contains("10.0.0.1"));
    assert_eq!(alert.host_name, None);
    Ok(())
}


#[test]
fn leases_without_a_usable_mac_are_counted_not_alerted() -> TestResult {
    let scope = tenant_scope("acme")?;
    let mut no_source = lease("aa:bb:cc:dd:ee:ff", "10.0.0.1", "", EXPIRE)?;
    no_source.event.source = None;
    let mut bad_mac = lease("aa:bb:cc:dd:ee:ff", "10.0.0.2", "", EXPIRE)?;
    bad_mac.event.source = Some(EndpointFields {
        mac: Some("not a mac".to_owned()),
        ip: Some("not an ip".to_owned()),
        ..EndpointFields::default()
    });
    let mut no_mac = lease("aa:bb:cc:dd:ee:ff", "10.0.0.3", "", EXPIRE)?;
    no_mac.event.source = Some(EndpointFields::default());
    assert_eq!((mac_of(&no_source), mac_of(&bad_mac), mac_of(&no_mac)), (None, None, None));
    assert_eq!(peer_fields(&bad_mac), (None, None));
    assert_eq!(peer_fields(&no_source), (None, None));
    let (alerts, rejected) = unknown_device_alerts(&scope, &[no_source, bad_mac, no_mac], &BTreeSet::new(), NOW_MICROS);
    assert_eq!((alerts.len(), rejected.no_mac), (0, EXTRA));
    Ok(())
}


#[test]
fn a_flood_is_cut_with_one_visible_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let leases = many_leases(MAX_UNKNOWN_PER_RUN + EXTRA)?;
    let (alerts, _rejected) = unknown_device_alerts(&scope, &leases, &BTreeSet::new(), NOW_MICROS);
    assert_eq!(alerts.len(), MAX_UNKNOWN_PER_RUN + 1);
    let flood = alerts.last().ok_or("no flood")?;
    assert_eq!(flood.rule_id, FLOOD_RULE_ID);
    assert_eq!(summary_of(flood)?.get("omitted").and_then(Value::as_u64), Some(EXTRA as u64));
    assert_eq!(
        alerts.iter().filter(|alert| alert.rule_id == UNKNOWN_RULE_ID).count(),
        MAX_UNKNOWN_PER_RUN
    );
    let exact = many_leases(MAX_UNKNOWN_PER_RUN)?;
    let (uncut, _uncut_rejected) = unknown_device_alerts(&scope, &exact, &BTreeSet::new(), NOW_MICROS);
    assert_eq!(uncut.len(), MAX_UNKNOWN_PER_RUN);
    Ok(())
}


#[test]
fn a_flood_alert_is_one_per_tenant_and_utc_day() -> TestResult {
    let scope = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let same_day = NOW_MICROS + MICROS_PER_SECOND;
    let next_day = NOW_MICROS + SECONDS_PER_DAY * MICROS_PER_SECOND;
    assert_eq!(flood_alert(&scope, 1, NOW_MICROS).id, flood_alert(&scope, EXTRA, same_day).id);
    assert_ne!(flood_alert(&scope, 1, NOW_MICROS).id, flood_alert(&scope, 1, next_day).id);
    assert_ne!(flood_alert(&scope, 1, NOW_MICROS).id, flood_alert(&other, 1, NOW_MICROS).id);
    assert_eq!(flood_alert(&scope, 1, NOW_MICROS).event_ids, ["flood", "day:2023-11-14"]);
    assert_eq!(
        (day_of(NOW_MICROS).as_str(), day_of(0).as_str(), day_of(u64::MAX).as_str()),
        ("2023-11-14", "1970-01-01", "9999-12-31")
    );
    Ok(())
}


#[test]
fn one_omitted_mac_still_raises_the_flood_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let leases = many_leases(MAX_UNKNOWN_PER_RUN + 1)?;
    let (alerts, _rejected) = unknown_device_alerts(&scope, &leases, &BTreeSet::new(), NOW_MICROS);
    assert_eq!(alerts.len(), MAX_UNKNOWN_PER_RUN + 1);
    let flood = alerts.last().ok_or("no flood")?;
    assert_eq!(flood.rule_id, FLOOD_RULE_ID);
    assert_eq!(summary_of(flood)?.get("omitted").and_then(Value::as_u64), Some(1));
    Ok(())
}


async fn run_once(exec: Executor<'_, '_>, scope: &TenantScope, leases: &[Converted]) -> Result<Vec<Alert>, Box<dyn std::error::Error>> {
    let lookup = alerted_in_batch(exec, scope, leases, &BTreeSet::new()).await;
    let (alerts, _rejected) = unknown_device_alerts_in_order(scope, leases, &lookup.skip, NOW_MICROS, &lookup.scan_order);
    store_unknown_device_alerts(exec, scope, &alerts).await?;
    advance_cursor(exec, scope, &lookup).await;
    Ok(alerts)
}


fn unknown_ids(alerts: &[Alert]) -> BTreeSet<String> {
    alerts
        .iter()
        .filter(|alert| alert.rule_id == UNKNOWN_RULE_ID)
        .map(|alert| alert.id.clone())
        .collect()
}


#[tokio::test]
async fn later_runs_reach_the_devices_the_first_run_cut() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(FLOOD_MACS)?;
    let first = run_once(&exec, &scope, &leases).await?;
    let second = run_once(&exec, &scope, &leases).await?;
    let third = run_once(&exec, &scope, &leases).await?;
    let fourth = run_once(&exec, &scope, &leases).await?;
    let (first_ids, second_ids, third_ids) = (unknown_ids(&first), unknown_ids(&second), unknown_ids(&third));
    let rest = FLOOD_MACS - MAX_UNKNOWN_PER_RUN - MAX_UNKNOWN_PER_RUN;
    assert_eq!(
        (first_ids.len(), second_ids.len(), third_ids.len()),
        (MAX_UNKNOWN_PER_RUN, MAX_UNKNOWN_PER_RUN, rest)
    );
    assert!(first_ids.is_disjoint(&second_ids) && first_ids.is_disjoint(&third_ids) && second_ids.is_disjoint(&third_ids));
    let first_flood = first.last().ok_or("no flood")?;
    assert_eq!(
        summary_of(first_flood)?.get("omitted").and_then(Value::as_u64),
        Some((FLOOD_MACS - MAX_UNKNOWN_PER_RUN) as u64)
    );
    assert_eq!((first.len(), third.len()), (MAX_UNKNOWN_PER_RUN + 1, rest));
    assert!(fourth.is_empty());
    assert_eq!(store.rows.lock().map_err(|_poisoned| "poisoned")?.len(), FLOOD_MACS + 1);
    Ok(())
}


#[tokio::test]
async fn a_lookup_failure_falls_back_to_batch_order() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store {
        fail_lookup: true,
        ..Store::default()
    };
    let exec = executor(&store);
    let leases = many_leases(FLOOD_MACS)?;
    assert!(alerted_in_batch(&exec, &scope, &leases, &BTreeSet::new()).await.skip.is_empty());
    let first = run_once(&exec, &scope, &leases).await?;
    let second = run_once(&exec, &scope, &leases).await?;
    assert_eq!((first.len(), second.len()), (MAX_UNKNOWN_PER_RUN + 1, MAX_UNKNOWN_PER_RUN + 1));
    assert_eq!(store.rows.lock().map_err(|_poisoned| "poisoned")?.len(), MAX_UNKNOWN_PER_RUN + 1);
    Ok(())
}


#[tokio::test]
async fn the_lookup_is_bounded_scoped_and_skipped_when_empty() -> TestResult {
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(MAX_LOOKUP_MACS + EXTRA)?;
    let all = candidate_macs(&leases, &BTreeSet::new());
    assert_eq!(all.len(), MAX_LOOKUP_MACS + EXTRA);
    let candidates: Vec<String> = all.into_iter().take(MAX_LOOKUP_MACS).collect();
    assert!(alerted_macs(&exec, &acme, &[]).await.is_empty());
    assert_eq!(*store.lookups.lock().map_err(|_poisoned| "poisoned")?, 0);
    let (alerts, _rejected) = unknown_device_alerts(&acme, &leases, &BTreeSet::new(), NOW_MICROS);
    store_unknown_device_alerts(&exec, &acme, &alerts).await?;
    assert_eq!(alerted_macs(&exec, &acme, &candidates).await.len(), MAX_UNKNOWN_PER_RUN);
    assert!(alerted_macs(&exec, &other, &candidates).await.is_empty());
    let too_many: Vec<String> = candidates.iter().chain(candidates.iter()).cloned().collect();
    assert_eq!(alerted_macs(&exec, &acme, &too_many).await.len(), MAX_UNKNOWN_PER_RUN);
    assert_eq!(*store.lookups.lock().map_err(|_poisoned| "poisoned")?, EXTRA);
    Ok(())
}


#[tokio::test]
async fn a_replay_inserts_nothing_and_a_flood_stores_the_cap_plus_one() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(MAX_UNKNOWN_PER_RUN + EXTRA)?;
    let (alerts, _rejected) = unknown_device_alerts(&scope, &leases, &BTreeSet::new(), NOW_MICROS);
    assert_eq!(store_unknown_device_alerts(&exec, &scope, &alerts).await?, MAX_UNKNOWN_PER_RUN + 1);
    assert_eq!(store_unknown_device_alerts(&exec, &scope, &alerts).await?, 0);
    assert_eq!(store.rows.lock().map_err(|_poisoned| "poisoned")?.len(), MAX_UNKNOWN_PER_RUN + 1);
    Ok(())
}


#[tokio::test]
async fn tenants_never_share_an_alert_or_a_known_set() -> TestResult {
    let acme = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = [lease("aa:bb:cc:dd:ee:ff", "10.0.0.1", "", EXPIRE)?];
    let acme_known = known(&["AA-BB-CC-DD-EE-FF"]);
    let (acme_alerts, _acme_rejected) = unknown_device_alerts(&acme, &leases, &acme_known, NOW_MICROS);
    let (other_alerts, _other_rejected) = unknown_device_alerts(&other, &leases, &BTreeSet::new(), NOW_MICROS);
    assert_eq!((acme_alerts.len(), other_alerts.len()), (0, 1));
    let (acme_open, _open_rejected) = unknown_device_alerts(&acme, &leases, &BTreeSet::new(), NOW_MICROS);
    assert_ne!(acme_open.first().map(|alert| &alert.id), other_alerts.first().map(|alert| &alert.id));
    assert!(other_alerts.iter().all(|alert| alert.tenant == "other"));
    let refused = store_unknown_device_alerts(&exec, &acme, &other_alerts).await;
    assert!(matches!(refused, Err(StoreError::TenantMismatch)));
    assert!(store.rows.lock().map_err(|_poisoned| "poisoned")?.is_empty());
    assert_eq!(store_unknown_device_alerts(&exec, &acme, &acme_open).await?, 1);
    assert_eq!(store_unknown_device_alerts(&exec, &other, &other_alerts).await?, 1);
    Ok(())
}


#[test]
fn the_id_is_the_tenant_rule_and_mac_only() -> TestResult {
    let scope = tenant_scope("acme")?;
    let leases = [lease("aa:bb:cc:dd:ee:ff", "10.0.0.1", "pc1", EXPIRE)?];
    let (alerts, _rejected) = unknown_device_alerts(&scope, &leases, &BTreeSet::new(), NOW_MICROS);
    let expected = alert_id("acme", UNKNOWN_RULE_ID, &["mac:AA-BB-CC-DD-EE-FF".to_owned()]);
    assert_eq!(alerts.first().map(|alert| alert.id.as_str()), Some(expected.as_str()));
    Ok(())
}


#[test]
fn times_are_clamped_to_the_store_range() -> TestResult {
    let scope = tenant_scope("acme")?;
    let mut leases = [lease("aa:bb:cc:dd:ee:ff", "10.0.0.1", "", EXPIRE)?];
    if let Some(first) = leases.first_mut() {
        first.cltt = -LIFETIME;
    }
    let (alerts, _rejected) = unknown_device_alerts(&scope, &leases, &BTreeSet::new(), u64::MAX);
    let alert = alerts.first().ok_or("no alert")?;
    assert_eq!((alert.event_time.as_str(), alert.created_micros), ("0", MAX_CREATED_MICROS));
    assert_eq!(micros_of(i64::MAX), MAX_CREATED_MICROS);
    Ok(())
}


#[tokio::test]
async fn an_executor_failure_is_propagated() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store {
        fail: true,
        ..Store::default()
    };
    let exec = executor(&store);
    let leases = [lease("aa:bb:cc:dd:ee:ff", "10.0.0.1", "", EXPIRE)?];
    let (alerts, _rejected) = unknown_device_alerts(&scope, &leases, &BTreeSet::new(), NOW_MICROS);
    assert!(matches!(
        store_unknown_device_alerts(&exec, &scope, &alerts).await,
        Err(StoreError::Pg(_))
    ));
    Ok(())
}


#[tokio::test]
async fn every_run_progresses_past_the_lookup_window_to_the_last_devices() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let total = MAX_LOOKUP_MACS + MAX_UNKNOWN_PER_RUN + EXTRA;
    let leases = many_leases(total)?;
    let last = leases.get(total - EXTRA..).ok_or("no tail")?;
    let last_ids = unknown_ids(&unknown_device_alerts(&scope, last, &BTreeSet::new(), NOW_MICROS).0);
    let runs = total / MAX_UNKNOWN_PER_RUN + TWO_CHUNKS;
    let mut inserted_per_run = Vec::new();
    for _run in 0..runs {
        let alerts = run_once(&exec, &scope, &leases).await?;
        inserted_per_run.push(unknown_ids(&alerts).len());
    }
    assert_eq!(inserted_per_run.iter().sum::<usize>(), total);
    assert!(inserted_per_run.iter().take(runs - 1).all(|count| *count > 0));
    let stored: BTreeSet<String> = store
        .rows
        .lock()
        .map_err(|_poisoned| "poisoned")?
        .iter()
        .map(|row| row.1.clone())
        .collect();
    assert!(last_ids.is_subset(&stored));
    Ok(())
}


#[tokio::test]
async fn the_chunk_count_per_run_is_capped() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(MAX_LOOKUP_MACS * (MAX_LOOKUP_CHUNKS + 1))?;
    for mac in candidate_macs(&leases, &BTreeSet::new()) {
        let id = alert_id("acme", UNKNOWN_RULE_ID, &[format!("mac:{mac}")]);
        store.rows.lock().map_err(|_poisoned| "poisoned")?.insert(("acme".to_owned(), id));
    }
    let before = *store.lookups.lock().map_err(|_poisoned| "poisoned")?;
    alerted_in_batch(&exec, &scope, &leases, &BTreeSet::new()).await;
    let after = *store.lookups.lock().map_err(|_poisoned| "poisoned")?;
    assert_eq!(after - before, MAX_LOOKUP_CHUNKS);
    Ok(())
}


#[tokio::test]
async fn a_lookup_failure_mid_chunk_keeps_the_earlier_answers_and_stops() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store {
        fail_from_lookup: Some(1),
        ..Store::default()
    };
    let exec = executor(&store);
    let leases = many_leases(MAX_LOOKUP_MACS * THREE_CHUNKS)?;
    let candidates = candidate_macs(&leases, &BTreeSet::new());
    for mac in candidates.iter().take(MAX_LOOKUP_MACS) {
        let id = alert_id("acme", UNKNOWN_RULE_ID, &[format!("mac:{mac}")]);
        store.rows.lock().map_err(|_poisoned| "poisoned")?.insert(("acme".to_owned(), id));
    }
    let alerted = alerted_in_batch(&exec, &scope, &leases, &BTreeSet::new()).await.skip;
    assert_eq!((alerted.len(), lookups_so_far(&store)), (MAX_LOOKUP_MACS * TWO_CHUNKS, 1));
    let known_or_alerted = alerted;
    let (alerts, _rejected) = unknown_device_alerts(&scope, &leases, &known_or_alerted, NOW_MICROS);
    assert_eq!(alerts.len(), MAX_UNKNOWN_PER_RUN + 1);
    Ok(())
}


#[tokio::test]
async fn a_second_tenant_with_the_same_macs_sees_none_as_alerted() -> TestResult {
    let other = tenant_scope("other")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(MAX_LOOKUP_MACS * TWO_CHUNKS)?;
    for mac in candidate_macs(&leases, &BTreeSet::new()) {
        let id = alert_id("acme", UNKNOWN_RULE_ID, &[format!("mac:{mac}")]);
        store.rows.lock().map_err(|_poisoned| "poisoned")?.insert(("acme".to_owned(), id));
    }
    let skipped = alerted_in_batch(&exec, &other, &leases, &BTreeSet::new()).await.skip;
    let candidates = candidate_macs(&leases, &BTreeSet::new());
    let second_chunk: BTreeSet<String> = candidates.iter().skip(MAX_LOOKUP_MACS).cloned().collect();
    assert_eq!(skipped, second_chunk);
    Ok(())
}


const SPOOFED: usize = MAX_LOOKUP_MACS * MAX_LOOKUP_CHUNKS;


const SIXTY_THOUSAND: usize = 60_000;


const MANY_GENUINE: usize = 300;


const GENUINE: usize = 3;


const FAR_CURSOR: usize = 1_000_001;


const WRAPPED_START: usize = 10;


const CAP_WARNING: &str = "lookup cap reached";


static ANCHOR: LazyLock<tracing::Dispatch> = LazyLock::new(|| tracing::Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


fn store_alerted_range(store: &Store, leases: &[Converted], range: std::ops::Range<usize>) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    let macs: Vec<String> = candidate_macs(leases, &BTreeSet::new())
        .into_iter()
        .enumerate()
        .filter(|(index, _mac)| range.contains(index))
        .map(|(_index, mac)| mac)
        .collect();
    macs.iter().try_for_each(|mac| {
        let id = alert_id("acme", UNKNOWN_RULE_ID, &[format!("mac:{mac}")]);
        store
            .rows
            .lock()
            .map(|mut rows| rows.insert(("acme".to_owned(), id)))
            .map(|_inserted| ())
            .map_err(|_poisoned| "poisoned")
    })?;
    Ok(macs.into_iter().collect())
}


fn store_alerted(store: &Store, leases: &[Converted], count: usize) -> Result<BTreeSet<String>, Box<dyn std::error::Error>> {
    store_alerted_range(store, leases, 0..count)
}


fn set_cursor(store: &Store, tenant: &str, value: &str) -> TestResult {
    store
        .cursors
        .lock()
        .map_err(|_poisoned| "poisoned")?
        .insert(tenant.to_owned(), value.to_owned());
    Ok(())
}


fn cursor_of(store: &Store, tenant: &str) -> Result<Option<String>, Box<dyn std::error::Error>> {
    Ok(store.cursors.lock().map_err(|_poisoned| "poisoned")?.get(tenant).cloned())
}


async fn run_cursor(exec: Executor<'_, '_>, scope: &TenantScope, leases: &[Converted]) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(unknown_ids(&run_once(exec, scope, leases).await?).len())
}


fn genuine_stored(store: &Store, leases: &[Converted], genuine: usize) -> Result<usize, Box<dyn std::error::Error>> {
    let tail = leases.get(leases.len() - genuine..).ok_or("no tail")?;
    let rows = store.rows.lock().map_err(|_poisoned| "poisoned")?;
    let stored = candidate_macs(tail, &BTreeSet::new())
        .iter()
        .filter(|mac| rows.contains(&("acme".to_owned(), alert_id("acme", UNKNOWN_RULE_ID, &[format!("mac:{mac}")]))))
        .count();
    Ok(stored)
}


#[tokio::test]
async fn spoofed_leases_filling_the_lookup_cap_do_not_hide_the_genuine_tail() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(SPOOFED + MANY_GENUINE)?;
    store_alerted(&store, &leases, SPOOFED)?;
    let mut stored_after = Vec::new();
    for _run in 0..THREE_CHUNKS {
        run_cursor(&exec, &scope, &leases).await?;
        stored_after.push(genuine_stored(&store, &leases, MANY_GENUINE)?);
    }
    assert_eq!(stored_after, [0, MAX_UNKNOWN_PER_RUN, MANY_GENUINE]);
    Ok(())
}


#[tokio::test]
async fn sixty_thousand_alerted_leases_still_reach_the_genuine_tail() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(SIXTY_THOUSAND + GENUINE)?;
    store_alerted(&store, &leases, SIXTY_THOUSAND)?;
    let before = lookups_so_far(&store);
    run_cursor(&exec, &scope, &leases).await?;
    assert_eq!(
        (
            lookups_so_far(&store) - before,
            genuine_stored(&store, &leases, GENUINE)?,
            cursor_of(&store, "acme")?
        ),
        (MAX_LOOKUP_CHUNKS, 0, Some("10".to_owned()))
    );
    run_cursor(&exec, &scope, &leases).await?;
    assert_eq!(genuine_stored(&store, &leases, GENUINE)?, GENUINE);
    Ok(())
}


#[tokio::test]
async fn the_cursor_moves_the_scan_whatever_the_clock_or_the_cadence() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(SIXTY_THOUSAND + GENUINE)?;
    store_alerted(&store, &leases, SIXTY_THOUSAND)?;
    let positions: Vec<Option<String>> = {
        let mut seen = Vec::new();
        for _run in 0..THREE_CHUNKS {
            run_cursor(&exec, &scope, &leases).await?;
            seen.push(cursor_of(&store, "acme")?);
        }
        seen
    };
    assert_eq!(positions, [Some("10".to_owned()), Some("7".to_owned()), Some("4".to_owned())]);
    Ok(())
}


#[tokio::test]
async fn the_scan_wraps_around_the_end_of_the_candidate_list() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(SPOOFED + GENUINE)?;
    let alerted = store_alerted(&store, &leases, SPOOFED)?;
    set_cursor(&store, "acme", &WRAPPED_START.to_string())?;
    let before = lookups_so_far(&store);
    let lookup = alerted_in_batch(&exec, &scope, &leases, &BTreeSet::new()).await;
    assert_eq!(lookups_so_far(&store) - before, MAX_LOOKUP_CHUNKS);
    let first_mac = candidate_macs(&leases, &BTreeSet::new()).into_iter().next().ok_or("no mac")?;
    assert!(lookup.skip.contains(&first_mac));
    assert_eq!(lookup.skip, alerted);
    assert_eq!(
        lookup.scan_order.first().map(String::as_str),
        candidate_macs(&leases, &BTreeSet::new())
            .get(WRAPPED_START * MAX_LOOKUP_MACS)
            .map(String::as_str)
    );
    Ok(())
}


#[tokio::test]
async fn a_wrapped_window_serves_its_own_tail_before_the_head_chunks() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(SIXTY_THOUSAND + GENUINE)?;
    store_alerted_range(&store, &leases, SPOOFED..SIXTY_THOUSAND)?;
    set_cursor(&store, "acme", &WRAPPED_START.to_string())?;
    let inserted = run_cursor(&exec, &scope, &leases).await?;
    assert_eq!((inserted, genuine_stored(&store, &leases, GENUINE)?), (MAX_UNKNOWN_PER_RUN, GENUINE));
    Ok(())
}


#[tokio::test]
async fn a_cursor_past_the_chunk_count_wraps_like_its_remainder() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(SPOOFED + GENUINE)?;
    store_alerted(&store, &leases, SPOOFED)?;
    set_cursor(&store, "acme", &FAR_CURSOR.to_string())?;
    let far = alerted_in_batch(&exec, &scope, &leases, &BTreeSet::new()).await;
    set_cursor(&store, "acme", &(FAR_CURSOR % (MAX_LOOKUP_CHUNKS + 1)).to_string())?;
    let remainder = alerted_in_batch(&exec, &scope, &leases, &BTreeSet::new()).await;
    assert_eq!(far, remainder);
    let empty = Store::default();
    let empty_exec = executor(&empty);
    let small = many_leases(GENUINE)?;
    assert_eq!(alerted_in_batch(&empty_exec, &scope, &small, &BTreeSet::new()).await.next_chunk, 0);
    assert_eq!(alerted_in_batch(&empty_exec, &scope, &[], &BTreeSet::new()).await, Lookup::default());
    Ok(())
}


#[test]
fn the_next_chunk_stays_on_a_chunk_with_leftover_fresh_macs_else_moves_on() -> TestResult {
    assert_eq!(next_chunk_of(0, 0, 0, 0), 0);
    assert_eq!(next_chunk_of(TWO_CHUNKS, THREE_CHUNKS, FIVE_CHUNKS, MAX_UNKNOWN_PER_RUN), 0);
    assert_eq!(next_chunk_of(TWO_CHUNKS, THREE_CHUNKS, FIVE_CHUNKS, MAX_UNKNOWN_PER_RUN + 1), FOUR_CHUNKS);
    assert_eq!(next_chunk_of(FOUR_CHUNKS, 1, FIVE_CHUNKS, 0), 0);
    Ok(())
}


#[tokio::test]
async fn each_tenant_has_its_own_cursor() -> TestResult {
    let scope = tenant_scope("acme")?;
    let other = tenant_scope("other")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(SIXTY_THOUSAND + GENUINE)?;
    store_alerted(&store, &leases, SIXTY_THOUSAND)?;
    run_cursor(&exec, &scope, &leases).await?;
    assert_eq!((cursor_of(&store, "acme")?, cursor_of(&store, "other")?), (Some("10".to_owned()), None));
    let lookup = alerted_in_batch(&exec, &other, &leases, &BTreeSet::new()).await;
    assert_eq!(lookup.found, 0);
    advance_cursor(&exec, &other, &lookup).await;
    assert_eq!(
        (cursor_of(&store, "acme")?, cursor_of(&store, "other")?),
        (Some("10".to_owned()), Some("0".to_owned()))
    );
    Ok(())
}


#[tokio::test]
async fn a_deleted_cursor_restarts_at_the_first_chunk() -> TestResult {
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let leases = many_leases(SIXTY_THOUSAND + GENUINE)?;
    store_alerted(&store, &leases, SIXTY_THOUSAND)?;
    run_cursor(&exec, &scope, &leases).await?;
    store.cursors.lock().map_err(|_poisoned| "poisoned")?.clear();
    assert_eq!(read_cursor(&exec, &scope).await, 0);
    run_cursor(&exec, &scope, &leases).await?;
    assert_eq!(cursor_of(&store, "acme")?, Some("10".to_owned()));
    Ok(())
}


fn capture_dispatch() -> Result<(Arc<std::fs::File>, tracing::Dispatch), Box<dyn std::error::Error>> {
    let capture = Arc::new(tempfile::tempfile()?);
    let writer = Arc::clone(&capture);
    let dispatch = tracing::Dispatch::new(
        tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(move || Arc::clone(&writer))
            .finish(),
    );
    Ok((capture, dispatch))
}


fn captured_text(capture: &Arc<std::fs::File>) -> Result<String, Box<dyn std::error::Error>> {
    let mut text = String::new();
    let mut file: &std::fs::File = capture;
    file.seek(SeekFrom::Start(0))?;
    file.read_to_string(&mut text)?;
    Ok(text)
}


#[tokio::test]
async fn a_failed_cursor_write_warns_once_and_the_next_run_repeats_from_the_old_cursor() -> TestResult {
    std::sync::LazyLock::force(&ANCHOR);
    let scope = tenant_scope("acme")?;
    let store = Store {
        fail_cursor_write: true,
        ..Store::default()
    };
    let exec = executor(&store);
    let leases = many_leases(SIXTY_THOUSAND + GENUINE)?;
    store_alerted(&store, &leases, SPOOFED)?;
    set_cursor(&store, "acme", &WRAPPED_START.to_string())?;
    let (capture, dispatch) = capture_dispatch()?;
    let guard = tracing::dispatcher::set_default(&dispatch);
    let first = run_cursor(&exec, &scope, &leases).await?;
    drop(guard);
    let text = captured_text(&capture)?;
    assert_eq!(text.matches("cursor not stored").count(), 1, "{text}");
    assert_eq!((first > 0, cursor_of(&store, "acme")?), (true, Some(WRAPPED_START.to_string())));
    Ok(())
}


#[tokio::test]
async fn an_unreadable_cursor_warns_once_and_starts_at_the_first_chunk() -> TestResult {
    std::sync::LazyLock::force(&ANCHOR);
    let scope = tenant_scope("acme")?;
    let failing = Store {
        fail_cursor_read: true,
        ..Store::default()
    };
    let failing_exec = executor(&failing);
    let garbled = Store::default();
    let garbled_exec = executor(&garbled);
    set_cursor(&garbled, "acme", "not a number")?;
    let valid = Store::default();
    let valid_exec = executor(&valid);
    set_cursor(&valid, "acme", &STORED_CURSOR.to_string())?;
    let (capture, dispatch) = capture_dispatch()?;
    let guard = tracing::dispatcher::set_default(&dispatch);
    let answers = (
        read_cursor(&failing_exec, &scope).await,
        read_cursor(&garbled_exec, &scope).await,
        read_cursor(&valid_exec, &scope).await,
    );
    write_cursor(&valid_exec, &scope, GENUINE).await;
    drop(guard);
    let text = captured_text(&capture)?;
    assert_eq!(answers, (0, 0, STORED_CURSOR));
    assert_eq!(text.matches("cursor unreadable").count(), TWO_CHUNKS, "{text}");
    assert_eq!(cursor_of(&valid, "acme")?, Some(GENUINE.to_string()));
    Ok(())
}


#[test]
fn the_cursor_statements_bind_the_tenant_and_the_migration_is_valid() -> TestResult {
    assert!(CURSOR_READ_SQL.contains("tenant = $1") && CURSOR_WRITE_SQL.contains("VALUES ($1,") && CURSOR_WRITE_SQL.contains("ON CONFLICT (tenant)"));
    check_namespace(MIGRATION_NAMESPACE)?;
    check_embedded(&MIGRATIONS)?;
    Ok(())
}


#[tokio::test]
async fn the_cap_warning_is_emitted_once_per_capped_run_only() -> TestResult {
    std::sync::LazyLock::force(&ANCHOR);
    let scope = tenant_scope("acme")?;
    let store = Store::default();
    let exec = executor(&store);
    let capped = many_leases(SPOOFED + GENUINE)?;
    store_alerted(&store, &capped, SPOOFED)?;
    let exhausted = many_leases(GENUINE)?;
    let full = many_leases(MAX_UNKNOWN_PER_RUN)?;
    let (capture, dispatch) = capture_dispatch()?;
    let guard = tracing::dispatcher::set_default(&dispatch);
    alerted_in_batch(&exec, &scope, &capped, &BTreeSet::new()).await;
    let after_capped = capture.metadata()?.len();
    alerted_in_batch(&exec, &scope, &exhausted, &BTreeSet::new()).await;
    alerted_in_batch(&exec, &scope, &full, &BTreeSet::new()).await;
    drop(guard);
    let text = captured_text(&capture)?;
    assert!(after_capped > 0);
    assert_eq!(text.matches(CAP_WARNING).count(), 1, "{text}");
    assert!(
        text.contains("total=50003") && text.contains("scanned=10") && text.contains("start=0"),
        "{text}"
    );
    Ok(())
}
