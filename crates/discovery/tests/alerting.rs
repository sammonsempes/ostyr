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
use discovery::alerting::{identity_of, micros_of, store_unmanaged_alerts, unmanaged_alert, unmanaged_alerts};
use discovery::candidates::known_devices;
use discovery::model::{
    Candidate, HintCounters, Lease, LeaseHints, ServiceRef, Skipped, Stored, FLOOD_RULE_ID, MAX_ALERT_SERVICES, MAX_UNMANAGED_PER_RUN,
    UNMANAGED_RULE_ID,
};
use serde_json::Value;
use std::collections::BTreeSet;
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
    fail: bool,
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
    move |scope, _sql, params| -> RowFuture<'_> {
        if store.fail {
            Box::pin(ready(Err(PgError::InvalidTenant)))
        } else {
            Box::pin(ready(run(store, &scope, &params)))
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
            omitted: 0
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
