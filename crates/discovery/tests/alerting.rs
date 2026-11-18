#[path = "support/assets.rs"]
mod assets;
#[path = "support/consts.rs"]
mod consts;
#[path = "support/types.rs"]
mod types;


use alerts::id::alert_id;
use alerts::store::{MAX_CREATED_MICROS, MAX_TITLE_CHARS};
use alerts::types::RowFuture;
use assets::asset_with_mac;
use consts::{CLTT, MAC_A};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use discovery::alerting::raise_unmanaged_alerts;
use discovery::alerting::{identity_of, micros_of, store_unmanaged_alerts, unmanaged_alert, unmanaged_alerts};
use discovery::candidates::known_devices;
use discovery::cursor::{read_cursor, write_cursor, MIGRATIONS, MIGRATION_NAMESPACE, READ_SQL as CURSOR_READ_SQL, WRITE_SQL as CURSOR_WRITE_SQL};
use discovery::lookup::{next_chunk_of, ALERTED_SQL};
use discovery::model::{
    Candidate, HintCounters, Lease, LeaseHints, ServiceRef, Skipped, Stored, FLOOD_RULE_ID, MAX_ALERT_SERVICES, MAX_UNMANAGED_PER_RUN,
    UNMANAGED_RULE_ID,
};
use discovery::model::{LOOKUP_CHUNK, MAX_LOOKUP_CHUNKS};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::future::ready;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock, Mutex};
use types::TestResult;


const TENANT: &str = "acme";


const OTHER_TENANT: &str = "globex";


const MAC_B: &str = "AA-BB-CC-DD-EE-02";


const FIRST_MS: i64 = CLTT * MILLIS + FIRST_OFFSET_MS;


const LEASE_SECONDS: i64 = 3_600;


const DOUBLE_LEASE: i64 = 7_200;


const SERVICES_TOTAL: u64 = 7;


const OMITTED_SERVICES: usize = 2;


const SEEN_SPAN_MS: i64 = 1_000;


const SUBNET_WIDTH: usize = 200;


const HTTP: u16 = 80;


const TCP: u8 = 6;


const UDP: u8 = 17;


const FOUR_LEASES: usize = 4;


const PAIR: usize = 2;


const NOW_MICROS: u64 = 1_700_000_000_000_000;


const FLOOD_ADDRESSES: usize = 150;


const OMITTED: usize = FLOOD_ADDRESSES - MAX_UNMANAGED_PER_RUN;


const MANY_SERVICES: u16 = 5;


const BAD_HOSTNAME_BYTES: usize = 5_000;


const MILLIS: i64 = 1000;


const FIRST_OFFSET_MS: i64 = 5_000;


const STORE_LIMIT_FIELD: usize = 256;


static ANCHOR: LazyLock<tracing::Dispatch> = LazyLock::new(|| tracing::Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


#[derive(Clone, Default)]
struct Captured(Arc<Mutex<Vec<u8>>>);


impl std::io::Write for Captured {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0
            .lock()
            .map_err(|_poisoned| std::io::Error::other("poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


#[derive(Default)]
struct Store {
    rows: Mutex<BTreeSet<(String, String)>>,
    cursors: Mutex<BTreeMap<String, String>>,
    fail: bool,
    fail_insert: bool,
    fail_lookup: bool,
    fail_lookup_from: Option<usize>,
    lookup_calls: std::sync::atomic::AtomicUsize,
    fail_cursor_read: bool,
    fail_cursor_write: bool,
}


fn statement(store: &Store, scope: &TenantScope, sql: &str, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
    let tenant = tenant_of(scope).to_owned();
    if sql == ALERTED_SQL {
        let ids: Vec<String> = serde_json::from_str(params.first().ok_or(PgError::InvalidTenant)?).map_err(|_bad| PgError::InvalidTenant)?;
        let rows = store.rows.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
        Ok(ids
            .into_iter()
            .filter(|id| rows.contains(&(tenant.clone(), id.clone())))
            .map(|id| vec![id])
            .collect())
    } else if sql == CURSOR_READ_SQL {
        let cursors = store.cursors.lock().map_err(|_poisoned| PgError::InvalidTenant)?;
        Ok(cursors.get(&tenant).map_or_else(Vec::new, |text| vec![vec![text.clone()]]))
    } else if sql == CURSOR_WRITE_SQL {
        let next = params.first().ok_or(PgError::InvalidTenant)?.clone();
        store
            .cursors
            .lock()
            .map_err(|_poisoned| PgError::InvalidTenant)?
            .insert(tenant, next.clone());
        Ok(vec![vec![next]])
    } else {
        run(store, scope, params)
    }
}


fn later_lookup_fails(store: &Store) -> bool {
    let call = store.lookup_calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    store.fail_lookup_from.is_some_and(|from| call >= from)
}


fn refused(store: &Store, sql: &str) -> bool {
    store.fail
        || (store.fail_insert && sql != ALERTED_SQL && sql != CURSOR_READ_SQL && sql != CURSOR_WRITE_SQL)
        || (store.fail_lookup && sql == ALERTED_SQL)
        || (sql == ALERTED_SQL && later_lookup_fails(store))
        || (store.fail_cursor_read && sql == CURSOR_READ_SQL)
        || (store.fail_cursor_write && sql == CURSOR_WRITE_SQL)
}


fn run(store: &Store, scope: &TenantScope, params: &[String]) -> Result<Vec<Vec<String>>, PgError> {
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


fn executor(store: &Store) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'_> + '_ {
    move |scope, sql, params| -> RowFuture<'_> {
        if refused(store, sql) {
            Box::pin(ready(Err(PgError::InvalidTenant)))
        } else {
            Box::pin(ready(statement(store, &scope, sql, &params)))
        }
    }
}


fn candidate(address: &str, first_seen_ms: i64) -> Result<Candidate, Box<dyn std::error::Error>> {
    Ok(Candidate {
        address: address.parse::<IpAddr>()?,
        first_seen_ms,
        last_seen_ms: first_seen_ms + SEEN_SPAN_MS,
        services: vec![ServiceRef { port: HTTP, protocol: TCP }],
        services_omitted: 0,
    })
}


fn lease(mac: &str, hostname: Option<&str>, expires: i64) -> Lease {
    Lease {
        mac: mac.to_string(),
        hostname: hostname.map(str::to_string),
        cltt: CLTT,
        tenancy_start: CLTT,
        expires,
        released: false,
    }
}


fn hints(tenant: &str, entries: Vec<(&str, Lease)>) -> Result<LeaseHints, Box<dyn std::error::Error>> {
    let mut found = LeaseHints {
        tenant: tenant.to_string(),
        leases: Default::default(),
        counters: HintCounters::default(),
    };
    for (address, held) in entries {
        found.leases.insert(address.parse::<IpAddr>()?, held);
    }
    Ok(found)
}


fn run_alerts(scope: &TenantScope, found: &[Candidate], held: &LeaseHints) -> (Vec<alerts::model::Alert>, Skipped) {
    unmanaged_alerts(scope, found, held, &[], &known_devices([]), NOW_MICROS)
}


#[test]
fn a_valid_lease_mac_gives_a_mac_identity_and_none_gives_an_ip_identity() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let found = [candidate("10.0.0.5", FIRST_MS)?, candidate("10.0.0.6", FIRST_MS)?];
    let held = hints(TENANT, vec![("10.0.0.5", lease(MAC_A, None, CLTT + LEASE_SECONDS))])?;
    let (alerts, skipped) = run_alerts(&scope, &found, &held);
    let identities: Vec<&str> = alerts.iter().filter_map(|alert| alert.event_ids.first()).map(String::as_str).collect();
    assert_eq!(identities, [format!("mac:{MAC_A}"), "ip:10.0.0.6".to_string()]);
    assert_eq!(skipped, Skipped::default());
    assert!(alerts.iter().all(|alert| alert.rule_id == UNMANAGED_RULE_ID && alert.tenant == TENANT));
    assert_eq!(found.first().map(|first| identity_of(first, None)), Some("ip:10.0.0.5".to_string()));
    Ok(())
}


#[test]
fn an_expired_early_released_or_macless_lease_gives_an_ip_identity() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let found = [
        candidate("10.0.0.5", FIRST_MS)?,
        candidate("10.0.0.6", FIRST_MS)?,
        candidate("10.0.0.7", FIRST_MS)?,
        candidate("10.0.0.8", FIRST_MS)?,
    ];
    let released = Lease {
        released: true,
        ..lease(MAC_A, None, CLTT + LEASE_SECONDS)
    };
    let early = Lease {
        tenancy_start: CLTT + LEASE_SECONDS,
        ..lease(MAC_A, None, CLTT + DOUBLE_LEASE)
    };
    let held = hints(
        TENANT,
        vec![
            ("10.0.0.5", lease(MAC_A, None, CLTT)),
            ("10.0.0.6", released),
            ("10.0.0.7", early),
            ("10.0.0.8", lease("", None, CLTT + LEASE_SECONDS)),
        ],
    )?;
    let (alerts, _skipped) = run_alerts(&scope, &found, &held);
    assert!(alerts.iter().filter_map(|alert| alert.event_ids.first()).all(|id| id.starts_with("ip:")));
    assert_eq!(alerts.len(), FOUR_LEASES);
    Ok(())
}


#[test]
fn hints_of_another_tenant_are_ignored() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let found = [candidate("10.0.0.5", FIRST_MS)?];
    let held = hints(OTHER_TENANT, vec![("10.0.0.5", lease(MAC_A, None, CLTT + LEASE_SECONDS))])?;
    let (alerts, _skipped) = run_alerts(&scope, &found, &held);
    assert_eq!(
        alerts.first().and_then(|alert| alert.event_ids.first()).map(String::as_str),
        Some("ip:10.0.0.5")
    );
    Ok(())
}


#[test]
fn a_lease_mac_keying_a_cmdb_asset_and_a_known_address_raise_nothing() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let found = [
        candidate("10.0.0.5", FIRST_MS)?,
        candidate("10.0.0.6", FIRST_MS)?,
        candidate("10.0.0.7", FIRST_MS)?,
    ];
    let held = hints(
        TENANT,
        vec![
            ("10.0.0.5", lease(MAC_A, None, CLTT + LEASE_SECONDS)),
            ("10.0.0.7", lease(MAC_B, None, CLTT + LEASE_SECONDS)),
        ],
    )?;
    let inventory = [asset_with_mac("printer-1", MAC_A)];
    let known = known_devices(["10.0.0.6".parse::<IpAddr>()?]);
    let (alerts, skipped) = unmanaged_alerts(&scope, &found, &held, &inventory, &known, NOW_MICROS);
    assert_eq!(
        skipped,
        Skipped {
            known: 1,
            managed: 1,
            ..Skipped::default()
        }
    );
    assert_eq!(alerts.len(), 1);
    assert_eq!(
        alerts.first().and_then(|alert| alert.event_ids.first()).map(String::as_str),
        Some(format!("mac:{MAC_B}").as_str())
    );
    Ok(())
}


#[test]
fn an_expired_lease_does_not_hide_a_device_behind_an_asset_mac() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let found = [candidate("10.0.0.5", FIRST_MS)?];
    let held = hints(TENANT, vec![("10.0.0.5", lease(MAC_A, None, CLTT))])?;
    let inventory = [asset_with_mac("printer-1", MAC_A)];
    let (alerts, skipped) = unmanaged_alerts(&scope, &found, &held, &inventory, &known_devices([]), NOW_MICROS);
    assert_eq!((alerts.len(), skipped.managed), (1, 0));
    Ok(())
}


#[test]
fn a_rerun_gives_the_same_ids_and_a_second_tenant_distinct_ones() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let other = tenant_scope(OTHER_TENANT)?;
    let found = [candidate("10.0.0.5", FIRST_MS)?];
    let held = hints(TENANT, vec![])?;
    let first = run_alerts(&scope, &found, &held).0;
    let again = unmanaged_alerts(&scope, &found, &held, &[], &known_devices([]), NOW_MICROS + 1).0;
    let elsewhere = run_alerts(&other, &found, &hints(OTHER_TENANT, vec![])?).0;
    assert_eq!(first.first().map(|alert| &alert.id), again.first().map(|alert| &alert.id));
    assert_ne!(first.first().map(|alert| &alert.id), elsewhere.first().map(|alert| &alert.id));
    assert_eq!(
        first.first().map(|alert| alert.id.clone()),
        Some(alert_id(TENANT, UNMANAGED_RULE_ID, &["ip:10.0.0.5".to_string()]))
    );
    Ok(())
}


#[test]
fn the_run_is_capped_by_first_seen_and_a_flood_alert_names_the_rest() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let found = (0..FLOOD_ADDRESSES)
        .rev()
        .map(|index| {
            candidate(
                &format!("10.0.{}.{}", index / SUBNET_WIDTH, index % SUBNET_WIDTH + 1),
                FIRST_MS + i64::try_from(index)?,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (alerts, skipped) = run_alerts(&scope, &found, &hints(TENANT, vec![])?);
    assert_eq!(alerts.len(), MAX_UNMANAGED_PER_RUN + 1);
    assert_eq!(skipped.omitted, OMITTED);
    let flood = alerts.last().ok_or("no flood")?;
    assert_eq!(flood.rule_id, FLOOD_RULE_ID);
    assert!(flood.summary.text.contains(&format!("\"omitted\":{OMITTED}")));
    let last_kept = alerts.get(MAX_UNMANAGED_PER_RUN - 1).ok_or("no last")?;
    assert_eq!(last_kept.event_ids, ["ip:10.0.0.100"]);
    let (again, _skipped) = run_alerts(&scope, &found, &hints(TENANT, vec![])?);
    assert_eq!(flood.id, again.last().ok_or("no flood")?.id);
    Ok(())
}


#[test]
fn ties_in_first_seen_are_ordered_by_address() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let found = [candidate("10.0.0.9", FIRST_MS)?, candidate("10.0.0.2", FIRST_MS)?];
    let (alerts, _skipped) = run_alerts(&scope, &found, &hints(TENANT, vec![])?);
    let identities: Vec<&str> = alerts.iter().filter_map(|alert| alert.event_ids.first()).map(String::as_str).collect();
    assert_eq!(identities, ["ip:10.0.0.2", "ip:10.0.0.9"]);
    Ok(())
}


#[test]
fn a_hostile_hostname_is_cleaned_bounded_and_never_part_of_the_identity() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let found = candidate("10.0.0.5", FIRST_MS)?;
    let hostile = format!("a\u{1b}[31m\u{202e}b{}", "x".repeat(BAD_HOSTNAME_BYTES));
    let alert = unmanaged_alert(&scope, &found, Some(MAC_A), Some(&hostile), NOW_MICROS);
    assert!(!alert.summary.text.contains('\u{1b}'));
    assert!(!alert.summary.text.contains('\u{202e}'));
    assert!(alert.summary.text.len() < BAD_HOSTNAME_BYTES);
    assert_eq!(alert.id, unmanaged_alert(&scope, &found, Some(MAC_A), None, NOW_MICROS).id);
    assert!(alert.rule_title.chars().count() <= MAX_TITLE_CHARS.min(STORE_LIMIT_FIELD));
    assert!(alert.rule_title.contains("install the agent"));
    Ok(())
}


#[test]
fn the_alert_names_the_first_services_and_the_agent_proposal() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let mut found = candidate("10.0.0.5", FIRST_MS)?;
    found.services = (1..=MANY_SERVICES).map(|port| ServiceRef { port, protocol: UDP }).collect();
    found.services_omitted = OMITTED_SERVICES;
    let alert = unmanaged_alert(&scope, &found, None, None, NOW_MICROS);
    let summary: Value = serde_json::from_str(&alert.summary.text)?;
    assert_eq!(summary.get("services").and_then(Value::as_array).map(Vec::len), Some(MAX_ALERT_SERVICES));
    assert_eq!(summary.get("services_total").and_then(Value::as_u64), Some(SERVICES_TOTAL));
    assert_eq!(summary.get("proposal").and_then(Value::as_str), Some("install the agent ostyr-agent"));
    assert_eq!(summary.get("mac"), Some(&Value::Null));
    Ok(())
}


#[test]
fn times_are_clamped_to_the_range_the_store_accepts() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    assert_eq!(micros_of(-1), 0);
    assert_eq!(micros_of(i64::MAX), MAX_CREATED_MICROS);
    let found = candidate("10.0.0.5", FIRST_MS)?;
    let (alerts, _skipped) = unmanaged_alerts(&scope, &[found], &hints(TENANT, vec![])?, &[], &known_devices([]), u64::MAX);
    assert_eq!(alerts.first().map(|alert| alert.created_micros), Some(MAX_CREATED_MICROS));
    Ok(())
}


#[tokio::test]
async fn stored_alerts_are_inserted_once_and_a_rerun_inserts_nothing() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let store = Store::default();
    let exec = executor(&store);
    let found = [candidate("10.0.0.5", FIRST_MS)?, candidate("10.0.0.6", FIRST_MS)?];
    let (alerts, _skipped) = run_alerts(&scope, &found, &hints(TENANT, vec![])?);
    assert_eq!(store_unmanaged_alerts(&exec, &scope, &alerts).await, Stored { inserted: PAIR, failed: 0 });
    assert_eq!(store_unmanaged_alerts(&exec, &scope, &alerts).await, Stored { inserted: 0, failed: 0 });
    Ok(())
}


#[tokio::test]
async fn a_failing_store_is_counted_and_warns_once() -> TestResult {
    std::sync::LazyLock::force(&ANCHOR);
    let scope = tenant_scope(TENANT)?;
    let store = Store {
        fail: true,
        ..Store::default()
    };
    let exec = executor(&store);
    let found = [candidate("10.0.0.5", FIRST_MS)?, candidate("10.0.0.6", FIRST_MS)?];
    let (alerts, _skipped) = run_alerts(&scope, &found, &hints(TENANT, vec![])?);
    let captured = Captured::default();
    let writer = captured.clone();
    let dispatch = tracing::Dispatch::new(tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish());
    let guard = tracing::dispatcher::set_default(&dispatch);
    let stored = store_unmanaged_alerts(&exec, &scope, &alerts).await;
    drop(guard);
    assert_eq!(stored, Stored { inserted: 0, failed: PAIR });
    let text = String::from_utf8(captured.0.lock().map_err(|_poisoned| "poisoned")?.clone())?;
    assert_eq!(text.matches("were not stored").count(), 1);
    Ok(())
}


#[tokio::test]
async fn an_empty_alert_list_stores_nothing_and_does_not_warn() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let store = Store::default();
    let exec = executor(&store);
    assert_eq!(store_unmanaged_alerts(&exec, &scope, &[]).await, Stored::default());
    Ok(())
}


const BLOCK: usize = 256;


const PLANE: usize = 65_536;


const OLD_MS: i64 = 1_000_000;


const NEW_MS: i64 = 2_000_000;


const TWO_CHUNKS: usize = LOOKUP_CHUNK + MAX_UNMANAGED_PER_RUN + MAX_UNMANAGED_PER_RUN;


const OVER_ONE: usize = LOOKUP_CHUNK + MAX_UNMANAGED_PER_RUN;


const RUN_BOUND: usize = 2 + TWO_CHUNKS / MAX_UNMANAGED_PER_RUN;


const ELEVEN_CHUNKS: usize = LOOKUP_CHUNK * MAX_LOOKUP_CHUNKS + MAX_UNMANAGED_PER_RUN;


const PARTIAL_FRESH: usize = 50;


const WRAPPED_CURSOR: &str = "7";


fn address_of(index: usize) -> String {
    format!("10.{}.{}.{}", index / PLANE, index / BLOCK % BLOCK, index % BLOCK)
}


fn spoofed(count: usize, first_ms: i64) -> Result<Vec<Candidate>, Box<dyn std::error::Error>> {
    (0..count)
        .map(|index| candidate(&address_of(index), first_ms + i64::try_from(index)?))
        .collect()
}


fn pre_alert(store: &Store, found: &[Candidate]) -> TestResult {
    let mut rows = store.rows.lock().map_err(|_poisoned| "poisoned")?;
    found.iter().for_each(|one| {
        rows.insert((TENANT.to_owned(), alert_id(TENANT, UNMANAGED_RULE_ID, &[identity_of(one, None)])));
    });
    Ok(())
}


async fn raise(store: &Store, found: &[Candidate], held: &LeaseHints) -> Result<(Skipped, Stored), Box<dyn std::error::Error>> {
    let exec = executor(store);
    let scope = tenant_scope(TENANT)?;
    Ok(raise_unmanaged_alerts(&exec, &scope, found, held, &[], &known_devices([]), NOW_MICROS).await)
}


fn cursor_of(store: &Store) -> Result<Option<String>, Box<dyn std::error::Error>> {
    Ok(store.cursors.lock().map_err(|_poisoned| "poisoned")?.get(TENANT).cloned())
}


fn row_count(store: &Store) -> Result<usize, Box<dyn std::error::Error>> {
    Ok(store.rows.lock().map_err(|_poisoned| "poisoned")?.len())
}


fn has_row(store: &Store, address: &str) -> Result<bool, Box<dyn std::error::Error>> {
    let id = alert_id(TENANT, UNMANAGED_RULE_ID, &[format!("ip:{address}")]);
    Ok(store.rows.lock().map_err(|_poisoned| "poisoned")?.contains(&(TENANT.to_owned(), id)))
}


async fn warnings_of<Work: std::future::Future>(work: Work) -> Result<(Work::Output, String), Box<dyn std::error::Error>> {
    std::sync::LazyLock::force(&ANCHOR);
    let captured = Captured::default();
    let writer = captured.clone();
    let dispatch = tracing::Dispatch::new(tracing_subscriber::fmt().with_ansi(false).with_writer(move || writer.clone()).finish());
    let guard = tracing::dispatcher::set_default(&dispatch);
    let output = work.await;
    drop(guard);
    let text = String::from_utf8(captured.0.lock().map_err(|_poisoned| "poisoned")?.clone())?;
    Ok((output, text))
}


#[tokio::test]
async fn old_alerted_spoofed_addresses_do_not_hide_a_newer_real_device() -> TestResult {
    let store = Store::default();
    let held = hints(TENANT, vec![])?;
    let mut found = spoofed(MAX_UNMANAGED_PER_RUN, OLD_MS)?;
    let first = raise(&store, &found, &held).await?;
    assert_eq!((first.1.inserted, first.0.omitted), (MAX_UNMANAGED_PER_RUN, 0));
    found.push(candidate("192.168.9.9", NEW_MS)?);
    let second = raise(&store, &found, &held).await?;
    assert_eq!((second.1.inserted, second.0.omitted), (1, 0));
    assert!(has_row(&store, "192.168.9.9")?);
    let third = raise(&store, &found, &held).await?;
    assert_eq!(third.1.inserted, 0);
    Ok(())
}


#[tokio::test]
async fn a_set_larger_than_one_lookup_is_alerted_within_the_stated_runs() -> TestResult {
    let store = Store::default();
    let held = hints(TENANT, vec![])?;
    let found = spoofed(TWO_CHUNKS, OLD_MS)?;
    let mut inserted = 0;
    for _run in 0..RUN_BOUND {
        inserted += raise(&store, &found, &held).await?.1.inserted;
    }
    assert_eq!(inserted, TWO_CHUNKS + 1);
    assert_eq!(row_count(&store)?, TWO_CHUNKS + 1);
    let last = raise(&store, &found, &held).await?;
    assert_eq!((last.1.inserted, last.0.omitted), (0, 0));
    Ok(())
}


#[tokio::test]
async fn a_real_device_past_a_chunk_of_old_alerted_addresses_is_alerted_in_the_same_run() -> TestResult {
    let store = Store::default();
    let held = hints(TENANT, vec![])?;
    let found = spoofed(OVER_ONE, OLD_MS)?;
    pre_alert(&store, found.get(..LOOKUP_CHUNK).ok_or("short")?)?;
    let run = raise(&store, &found, &held).await?;
    assert_eq!((run.1.inserted, run.0.omitted), (MAX_UNMANAGED_PER_RUN, 0));
    assert!(has_row(&store, &address_of(OVER_ONE - 1))?);
    assert_eq!(cursor_of(&store)?, Some("0".to_owned()));
    Ok(())
}


#[tokio::test]
async fn a_cursor_past_the_chunk_count_wraps_and_starts_at_the_stored_chunk() -> TestResult {
    let store = Store::default();
    store
        .cursors
        .lock()
        .map_err(|_poisoned| "poisoned")?
        .insert(TENANT.to_owned(), WRAPPED_CURSOR.to_owned());
    let held = hints(TENANT, vec![])?;
    let found = spoofed(TWO_CHUNKS, OLD_MS)?;
    let run = raise(&store, &found, &held).await?;
    assert_eq!(run.1.inserted, MAX_UNMANAGED_PER_RUN + 1);
    assert!(has_row(&store, &address_of(LOOKUP_CHUNK))?);
    assert!(!has_row(&store, &address_of(0))?);
    assert_eq!(cursor_of(&store)?, Some("1".to_owned()));
    Ok(())
}


#[tokio::test]
async fn a_lookup_covers_at_most_the_chunk_cap_per_run_then_the_cursor_moves_on() -> TestResult {
    let store = Store::default();
    let held = hints(TENANT, vec![])?;
    let found = spoofed(ELEVEN_CHUNKS, OLD_MS)?;
    pre_alert(&store, found.get(..LOOKUP_CHUNK * MAX_LOOKUP_CHUNKS).ok_or("short")?)?;
    let (outcome, text) = warnings_of(raise(&store, &found, &held)).await?;
    let first = outcome?;
    assert_eq!(
        (first.1.inserted, first.0.deferred, first.0.omitted),
        (1, MAX_UNMANAGED_PER_RUN, MAX_UNMANAGED_PER_RUN)
    );
    assert_eq!(text.matches("lookup cap reached").count(), 1);
    assert_eq!(cursor_of(&store)?, Some(MAX_LOOKUP_CHUNKS.to_string()));
    let second = raise(&store, &found, &held).await?;
    assert_eq!(second.1.inserted, MAX_UNMANAGED_PER_RUN);
    Ok(())
}


#[tokio::test]
async fn two_addresses_of_one_mac_raise_one_alert() -> TestResult {
    let store = Store::default();
    let found = [candidate("10.0.0.5", FIRST_MS)?, candidate("10.0.0.6", FIRST_MS)?];
    let held = hints(
        TENANT,
        vec![
            ("10.0.0.5", lease(MAC_B, None, CLTT + LEASE_SECONDS)),
            ("10.0.0.6", lease(MAC_B, None, CLTT + LEASE_SECONDS)),
        ],
    )?;
    assert_eq!(raise(&store, &found, &held).await?.1.inserted, 1);
    Ok(())
}


#[tokio::test]
async fn a_failed_lookup_alerts_nothing_and_keeps_the_cursor() -> TestResult {
    let store = Store {
        fail_lookup: true,
        ..Store::default()
    };
    let held = hints(TENANT, vec![])?;
    let found = spoofed(MAX_UNMANAGED_PER_RUN + 1, OLD_MS)?;
    let (run, text) = warnings_of(raise(&store, &found, &held)).await?;
    let (skipped, stored) = run?;
    assert_eq!((stored, skipped.omitted), (Stored::default(), 0));
    assert!(skipped.lookup_failed);
    assert_eq!(text.matches("lookup failed").count(), 1);
    assert_eq!((row_count(&store)?, cursor_of(&store)?), (0, None));
    Ok(())
}


#[tokio::test]
async fn a_lookup_failing_on_a_later_chunk_alerts_nothing_and_keeps_the_cursor() -> TestResult {
    let store = Store {
        fail_lookup_from: Some(1),
        ..Store::default()
    };
    let held = hints(TENANT, vec![])?;
    let found = spoofed(TWO_CHUNKS, OLD_MS)?;
    pre_alert(&store, found.get(..LOOKUP_CHUNK - PARTIAL_FRESH).ok_or("short")?)?;
    let skipped_and_stored = raise(&store, &found, &held).await?;
    assert_eq!(skipped_and_stored.1, Stored::default());
    assert!(skipped_and_stored.0.lookup_failed);
    assert_eq!((row_count(&store)?, cursor_of(&store)?), (LOOKUP_CHUNK - PARTIAL_FRESH, None));
    Ok(())
}


#[tokio::test]
async fn a_refused_insert_keeps_the_cursor_so_the_next_run_repeats() -> TestResult {
    let store = Store {
        fail_insert: true,
        ..Store::default()
    };
    let held = hints(TENANT, vec![])?;
    let found = spoofed(PAIR, OLD_MS)?;
    let (run, _text) = warnings_of(raise(&store, &found, &held)).await?;
    assert_eq!(run?.1, Stored { inserted: 0, failed: PAIR });
    assert_eq!(cursor_of(&store)?, None);
    Ok(())
}


#[tokio::test]
async fn the_cursor_reads_as_zero_when_missing_unreadable_or_not_a_number() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let store = Store::default();
    let exec = executor(&store);
    assert_eq!(read_cursor(&exec, &scope).await, 0);
    store
        .cursors
        .lock()
        .map_err(|_poisoned| "poisoned")?
        .insert(TENANT.to_owned(), "x".to_owned());
    let (bad_position, bad_text) = warnings_of(read_cursor(&exec, &scope)).await?;
    assert_eq!((bad_position, bad_text.matches("unreadable").count()), (0, 1));
    let broken = Store {
        fail_cursor_read: true,
        ..Store::default()
    };
    let broken_exec = executor(&broken);
    let (position, text) = warnings_of(read_cursor(&broken_exec, &scope)).await?;
    assert_eq!((position, text.matches("unreadable").count()), (0, 1));
    Ok(())
}


#[tokio::test]
async fn a_failed_cursor_write_warns_once() -> TestResult {
    let scope = tenant_scope(TENANT)?;
    let store = Store {
        fail_cursor_write: true,
        ..Store::default()
    };
    let exec = executor(&store);
    let ((), text) = warnings_of(write_cursor(&exec, &scope, 1)).await?;
    assert_eq!(text.matches("not stored").count(), 1);
    let working = Store::default();
    let working_exec = executor(&working);
    write_cursor(&working_exec, &scope, PAIR).await;
    assert_eq!(cursor_of(&working)?, Some(PAIR.to_string()));
    Ok(())
}


#[test]
fn the_next_chunk_stays_on_a_chunk_with_more_fresh_ids_than_the_run_alerts() -> TestResult {
    assert_eq!(next_chunk_of(0, 1, PAIR, MAX_UNMANAGED_PER_RUN + 1), 0);
    assert_eq!(next_chunk_of(0, 1, PAIR, MAX_UNMANAGED_PER_RUN), 1);
    assert_eq!(next_chunk_of(1, 1, PAIR, 0), 0);
    assert_eq!(next_chunk_of(0, 0, 0, 0), 0);
    assert_eq!(MIGRATION_NAMESPACE, "discovery");
    assert_eq!(MIGRATIONS.len(), 1);
    Ok(())
}
