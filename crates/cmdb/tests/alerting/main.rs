#[path = "../store/memory.rs"]
mod memory;
#[path = "../store/types.rs"]
mod types;


use alerts::model::Severity;
use alerts::store::{INSERT_SQL, MAX_EVENT_ID_CHARS};
use cmdb::alerting::{
    asset_ref, reappeared_alerts, reconcile_with_alerts, store_reappeared_alerts, AlertCounts, FLOOD_RULE_ID, MAX_REAPPEARED_PER_RUN,
    REAPPEARED_RULE_ID,
};
use cmdb::model::{AssetKind, Event, IdentityKey, Lifecycle, Limits, Observation};
use cmdb::summary::MAX_ID_BYTES;
use cmdb::types::{RowFuture, TruthMap};
use core_pg::error::PgError;
use core_pg::scope::{tenant_of, tenant_scope, TenantScope};
use memory::{handle, lock, Db};
use serde_json::Value;
use std::future::ready;
use std::io::Write;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex};
use tracing::Dispatch;
use types::TestResult;


const NOW_MICROS: u64 = 1_700_000_000_000_000;


const FLOODING: usize = 150;


const OMITTED: usize = 50;


const ONE_DAY_MICROS: u64 = 86_400_000_000;


const RETIRED_ASSET: &str = "serial_number:SN1";


#[derive(Default)]
pub struct AlertStore {
    pub rows: Mutex<Vec<(String, Value)>>,
    pub fail: AtomicBool,
}


pub static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


pub struct CapturedWriter {
    pub bytes: Arc<Mutex<Vec<u8>>>,
}


impl Write for CapturedWriter {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        lock(&self.bytes).extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


pub fn logged(captured: &Arc<Mutex<Vec<u8>>>) -> String {
    String::from_utf8_lossy(&lock(captured)).into_owned()
}


pub fn executor<'a>(db: &'a Db, store: &'a AlertStore) -> impl Fn(TenantScope, &'static str, Vec<String>) -> RowFuture<'a> + 'a {
    move |scope, sql, params| -> RowFuture<'a> {
        let answer = if sql != INSERT_SQL {
            handle(db, &scope, sql, &params)
        } else if store.fail.load(Ordering::SeqCst) {
            Err(PgError::InvalidTenant)
        } else {
            let docs: Vec<Value> = params.first().and_then(|text| serde_json::from_str(text).ok()).unwrap_or_else(Vec::new);
            let mut rows = lock(&store.rows);
            let tenant = tenant_of(&scope).to_owned();
            let new = docs
                .into_iter()
                .filter(|doc| {
                    let id = doc.get("id").and_then(Value::as_str).unwrap_or("");
                    !rows
                        .iter()
                        .any(|(held, other)| *held == tenant && other.get("id").and_then(Value::as_str) == Some(id))
                })
                .collect::<Vec<Value>>();
            let count = new.len();
            rows.extend(new.into_iter().map(|doc| (tenant.clone(), doc)));
            Ok(vec![vec![count.to_string()]])
        };
        Box::pin(ready(answer))
    }
}


pub fn observation(source: &str, serial: &str, attributes: &[(&str, &str)]) -> Observation {
    Observation {
        source: source.to_owned(),
        kind: AssetKind::Server,
        keys: [(IdentityKey::SerialNumber, serial.to_owned())].into_iter().collect(),
        attributes: attributes.iter().map(|(name, value)| ((*name).to_owned(), (*value).to_owned())).collect(),
    }
}


pub fn set_lifecycle(db: &Db, tenant_name: &str, lifecycle: &str) {
    let mut tenants = lock(&db.tenants);
    tenants
        .entry(tenant_name.to_owned())
        .or_default()
        .assets
        .entry(RETIRED_ASSET.to_owned())
        .and_modify(|asset| {
            asset.1 = lifecycle.to_owned();
        });
}


pub fn stored_in(store: &AlertStore, tenant_name: &str) -> Vec<Value> {
    lock(&store.rows)
        .iter()
        .filter(|(held, _doc)| held == tenant_name)
        .map(|(_held, doc)| doc.clone())
        .collect()
}


pub fn field(doc: &Value, name: &str) -> String {
    doc.get(name).and_then(Value::as_str).unwrap_or("").to_owned()
}


async fn seen_after(db: &Db, store: &AlertStore, tenant_name: &str, lifecycle: &str) -> Result<AlertCounts, Box<dyn std::error::Error>> {
    let exec = executor(db, store);
    let scope = tenant_scope(tenant_name)?;
    let limits = Limits::default();
    reconcile_with_alerts(&exec, &scope, &observation("agent", "SN1", &[]), &TruthMap::new(), &limits, NOW_MICROS).await?;
    set_lifecycle(db, tenant_name, lifecycle);
    let (_stored, counts) = reconcile_with_alerts(&exec, &scope, &observation("agent", "SN1", &[]), &TruthMap::new(), &limits, NOW_MICROS).await?;
    Ok(counts)
}


#[tokio::test]
async fn a_retired_asset_seen_twice_gives_one_alert() -> TestResult {
    let db = Db::default();
    let store = AlertStore::default();
    let first = seen_after(&db, &store, "acme", "retired").await?;
    assert_eq!((first.inserted, first.existing, first.omitted, first.alert_failed), (1, 0, 0, 0));
    let exec = executor(&db, &store);
    let scope = tenant_scope("acme")?;
    let later = NOW_MICROS + ONE_DAY_MICROS;
    let (_stored, second) = reconcile_with_alerts(
        &exec,
        &scope,
        &observation("agent", "SN1", &[]),
        &TruthMap::new(),
        &Limits::default(),
        later,
    )
    .await?;
    assert_eq!((second.inserted, second.existing), (0, 1));
    let rows = stored_in(&store, "acme");
    assert_eq!(rows.len(), 1);
    let doc = rows.first().ok_or("no alert")?;
    assert_eq!(field(doc, "rule_id"), REAPPEARED_RULE_ID);
    assert_eq!(field(doc, "severity"), Severity::Medium.to_string());
    assert!(field(doc, "summary").contains(RETIRED_ASSET));
    assert!(field(doc, "summary").contains("agent"));
    Ok(())
}


#[tokio::test]
async fn a_destroyed_asset_is_high() -> TestResult {
    let db = Db::default();
    let store = AlertStore::default();
    seen_after(&db, &store, "acme", "destroyed").await?;
    let rows = stored_in(&store, "acme");
    assert_eq!(field(rows.first().ok_or("no alert")?, "severity"), Severity::High.to_string());
    Ok(())
}


#[tokio::test]
async fn in_service_and_maintenance_assets_give_none() -> TestResult {
    let db = Db::default();
    let store = AlertStore::default();
    let in_service = seen_after(&db, &store, "acme", "in_service").await?;
    assert_eq!(in_service, AlertCounts::default());
    let maintenance = seen_after(&db, &store, "acme", "in_maintenance").await?;
    assert_eq!(maintenance, AlertCounts::default());
    assert!(lock(&store.rows).is_empty());
    let scope = tenant_scope("acme")?;
    let events = [
        Event::Reappeared {
            asset: "a".to_owned(),
            lifecycle: Lifecycle::InService,
        },
        Event::Reappeared {
            asset: "b".to_owned(),
            lifecycle: Lifecycle::Ordered,
        },
        Event::Reappeared {
            asset: "c".to_owned(),
            lifecycle: Lifecycle::InMaintenance,
        },
        Event::Created { asset: "d".to_owned() },
    ];
    assert_eq!(reappeared_alerts(&scope, "agent", &events, NOW_MICROS), (Vec::new(), 0));
    Ok(())
}


#[tokio::test]
async fn two_tenants_with_the_same_asset_get_two_alerts() -> TestResult {
    let db = Db::default();
    let store = AlertStore::default();
    seen_after(&db, &store, "acme", "retired").await?;
    seen_after(&db, &store, "zeta", "retired").await?;
    let acme = stored_in(&store, "acme");
    let zeta = stored_in(&store, "zeta");
    assert_eq!((acme.len(), zeta.len()), (1, 1));
    assert_ne!(field(acme.first().ok_or("none")?, "id"), field(zeta.first().ok_or("none")?, "id"));
    assert_ne!(asset_ref("acme", RETIRED_ASSET), asset_ref("zeta", RETIRED_ASSET));
    Ok(())
}


#[test]
fn a_flood_is_cut_with_one_visible_alert() -> TestResult {
    let scope = tenant_scope("acme")?;
    let events: Vec<Event> = (0..FLOODING)
        .map(|index| Event::Reappeared {
            asset: format!("serial_number:{index}"),
            lifecycle: Lifecycle::Retired,
        })
        .collect();
    let (alerts, omitted) = reappeared_alerts(&scope, "agent", &events, NOW_MICROS);
    assert_eq!((alerts.len(), omitted), (MAX_REAPPEARED_PER_RUN + 1, OMITTED));
    let flood = alerts.last().ok_or("no flood")?;
    assert_eq!(flood.rule_id, FLOOD_RULE_ID);
    assert!(flood.rule_title.contains("50 more"));
    assert!(flood.summary.text.contains("\"omitted\":50"));
    let (again, _omitted) = reappeared_alerts(&scope, "agent", &events, NOW_MICROS + 1);
    assert_eq!(again.last().map(|alert| &alert.id), Some(&flood.id));
    let (twice, none) = reappeared_alerts(
        &scope,
        "agent",
        &[events.first().ok_or("none")?.clone(), events.first().ok_or("none")?.clone()],
        NOW_MICROS,
    );
    assert_eq!((twice.len(), none), (1, 0));
    Ok(())
}


#[tokio::test]
async fn a_failing_alert_store_leaves_the_cmdb_change_and_the_next_call_inserts() -> TestResult {
    let _anchor = LazyLock::force(&ANCHOR);
    let captured: Arc<Mutex<Vec<u8>>> = Arc::default();
    let sink = Arc::clone(&captured);
    let dispatch = Dispatch::new(
        tracing_subscriber::fmt()
            .with_writer(move || CapturedWriter { bytes: Arc::clone(&sink) })
            .with_ansi(false)
            .finish(),
    );
    let guard = tracing::dispatcher::set_default(&dispatch);
    let db = Db::default();
    let store = AlertStore::default();
    let exec = executor(&db, &store);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    reconcile_with_alerts(&exec, &scope, &observation("agent", "SN1", &[]), &TruthMap::new(), &limits, NOW_MICROS).await?;
    set_lifecycle(&db, "acme", "retired");
    store.fail.store(true, Ordering::SeqCst);
    let applies_before = *lock(&db.apply_calls);
    let (stored, counts) = reconcile_with_alerts(
        &exec,
        &scope,
        &observation("agent", "SN1", &[("owner", "ann")]),
        &TruthMap::new(),
        &limits,
        NOW_MICROS,
    )
    .await?;
    assert_eq!((counts.alert_failed, counts.inserted), (1, 0));
    assert_eq!(stored.outcome.events.len(), 1);
    assert_eq!(*lock(&db.apply_calls), applies_before + 1);
    assert!(lock(&store.rows).is_empty());
    assert_eq!(logged(&captured).matches("cmdb alert insert failed").count(), 1);
    store.fail.store(false, Ordering::SeqCst);
    let (_stored, retried) = reconcile_with_alerts(&exec, &scope, &observation("agent", "SN1", &[]), &TruthMap::new(), &limits, NOW_MICROS).await?;
    assert_eq!((retried.inserted, retried.alert_failed), (1, 0));
    drop(guard);
    Ok(())
}


#[tokio::test]
async fn an_observation_value_never_reaches_the_alert() -> TestResult {
    let db = Db::default();
    let store = AlertStore::default();
    let exec = executor(&db, &store);
    let scope = tenant_scope("acme")?;
    let limits = Limits::default();
    reconcile_with_alerts(&exec, &scope, &observation("agent", "SN1", &[]), &TruthMap::new(), &limits, NOW_MICROS).await?;
    set_lifecycle(&db, "acme", "retired");
    reconcile_with_alerts(
        &exec,
        &scope,
        &observation("agent", "SN1", &[("owner", "MARKERVALUE")]),
        &TruthMap::new(),
        &limits,
        NOW_MICROS,
    )
    .await?;
    let rows = stored_in(&store, "acme");
    assert_eq!(rows.len(), 1);
    assert!(!format!("{rows:?}").contains("MARKERVALUE"));
    Ok(())
}


#[tokio::test]
async fn a_long_asset_id_fits_the_event_id_and_a_refused_observation_alerts_nothing() -> TestResult {
    let scope = tenant_scope("acme")?;
    let long = "x".repeat(MAX_ID_BYTES);
    let events = [Event::Reappeared {
        asset: long,
        lifecycle: Lifecycle::Destroyed,
    }];
    let (alerts, _omitted) = reappeared_alerts(&scope, "agent", &events, NOW_MICROS);
    assert!(alerts.iter().all(|alert| alert.event_ids.iter().all(|id| id.len() <= MAX_EVENT_ID_CHARS)));
    let db = Db::default();
    let store = AlertStore::default();
    let exec = executor(&db, &store);
    let counts = store_reappeared_alerts(&exec, &scope, &alerts, 0).await;
    assert_eq!((counts.inserted, counts.alert_failed), (1, 0));
    let hostile = observation("agent\u{1b}", "SN1", &[]);
    let refused = reconcile_with_alerts(&exec, &scope, &hostile, &TruthMap::new(), &Limits::default(), NOW_MICROS).await;
    assert!(refused.is_err());
    assert_eq!(lock(&store.rows).len(), 1);
    Ok(())
}
