#[path = "common/types.rs"]
mod types;


use alerts::error::StoreError;
use alerts::id::alert_id;
use alerts::model::{Alert, Severity};
use alerts::store::{MAX_CREATED_MICROS, MAX_TITLE_CHARS};
use alerts::types::{Executor, RowFuture};
use core_export::ecs::{EndpointFields, HostFields};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use dhcp_kea::alerting::{
    alerted_in_batch, alerted_macs, candidate_macs, day_of, flood_alert, mac_of, micros_of, peer_fields, store_unknown_device_alerts,
    unknown_device_alerts, ALERTED_SQL, FLOOD_RULE_ID, MAX_LOOKUP_CHUNKS, MAX_LOOKUP_MACS, MAX_UNKNOWN_PER_RUN, MICROS_PER_SECOND, SECONDS_PER_DAY,
    UNKNOWN_RULE_ID,
};
use dhcp_kea::header::parse_header;
use dhcp_kea::row::{convert_row, Converted};
use serde_json::Value;
use std::collections::BTreeSet;
use std::future::ready;
use std::sync::Mutex;
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


const HOSTILE_BYTES: usize = 4_096;


const OCTET_RANGE: usize = 256;


const SUMMARY_LIMIT: usize = 512;


#[derive(Default)]
pub struct Store {
    pub rows: Mutex<BTreeSet<(String, String)>>,
    pub fail: bool,
    pub fail_lookup: bool,
    pub lookups: Mutex<usize>,
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


pub fn executor<'a>(store: &'a Store) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> {
        if store.fail || (store.fail_lookup && sql == ALERTED_SQL) {
            Box::pin(ready(Err(PgError::InvalidTenant)))
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
    let skip = alerted_in_batch(exec, scope, leases, &BTreeSet::new()).await;
    let (alerts, _rejected) = unknown_device_alerts(scope, leases, &skip, NOW_MICROS);
    store_unknown_device_alerts(exec, scope, &alerts).await?;
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
    assert!(alerted_in_batch(&exec, &scope, &leases, &BTreeSet::new()).await.is_empty());
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
    let runs = total / MAX_UNKNOWN_PER_RUN + 1;
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
