use crate::error::DetectionError;
use crate::id::{alert_id, event_identity};
use crate::model::{AlertRecord, AlertStore, Detector};
use crate::types::{AlertSinkFn, EngineMap};
use core_config::reload::ReloadEngine;
use core_config::types::BoxError;
use serde_json::Value;
use siem_ingest::model::Document;
use siem_ingest::tenant::is_tenant_char;
use siem_ingest::types::SinkFn;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use stream_correlation::checkpoint::{load_checkpoint, save_checkpoint};
use stream_correlation::cli::EVENT_ID_FIELD;
use stream_correlation::engine::{new_engine, process_event, snapshot, Engine};
use stream_correlation::field::{lookup, scalar_text};
use stream_correlation::ruleset::RuleSet;
use stream_correlation::window::{Alert, State};
use tracing::{debug, warn};


pub fn new_detector(
    rules: Arc<ReloadEngine<RuleSet>>,
    store: Arc<AlertStore>,
    commit: AlertSinkFn,
    limits: (usize, usize),
    checkpoint_dir: PathBuf,
) -> Detector {
    Detector {
        rules,
        engines: Mutex::new(EngineMap::new()),
        store,
        commit,
        max_alerts: limits.0,
        max_tenants: limits.1,
        checkpoint_dir,
        refused: AtomicU64::new(0),
        invalid: AtomicU64::new(0),
        dirty: AtomicBool::new(false),
    }
}


/// The tenant names a file, so it is one token of letters, digits, `-` and `_`.
pub fn valid_tenant(tenant: &str) -> bool {
    !tenant.is_empty() && tenant.chars().all(is_tenant_char)
}


pub fn checkpoint_path(directory: &Path, tenant: &str) -> PathBuf {
    directory.join(format!("{tenant}.json"))
}


/// The tenant's engine, created on first use from its checkpoint; windows are per tenant, so one tenant's events never join another's.
pub fn engine_for(detector: &Detector, tenant: &str) -> Result<Arc<Engine>, DetectionError> {
    let mut engines = detector.engines.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(engine) = engines.get(tenant) {
        Ok(Arc::clone(engine))
    } else if !valid_tenant(tenant) {
        Err(DetectionError::InvalidTenant)
    } else if engines.len() >= detector.max_tenants {
        Err(DetectionError::TooManyTenants { max: detector.max_tenants })
    } else {
        let restored = load_checkpoint(&checkpoint_path(&detector.checkpoint_dir, tenant))?;
        debug!(restored = restored.is_some(), "tenant engine started, no checkpoint means a first start");
        let engine = Arc::new(new_engine(Arc::clone(&detector.rules), restored.unwrap_or_default()));
        engines.insert(tenant.to_owned(), Arc::clone(&engine));
        Ok(engine)
    }
}


/// Puts back the windows a failed batch had changed, so its redelivery replays from the same state and yields the same alert ids.
pub fn restore_state(engine: &Engine, saved: State) {
    *engine.state.lock().unwrap_or_else(PoisonError::into_inner) = saved;
}


pub fn identity_of(event: &Value, payload: &[u8]) -> String {
    let id = lookup(event, EVENT_ID_FIELD).and_then(scalar_text);
    event_identity(id.as_deref(), payload)
}


/// The alerts of every document; a payload that is not JSON is counted and skipped (the bus adapter already refuses those). The payload's own `tenant` is never read.
pub fn collect_alerts(engine: &Engine, documents: &[Document], invalid: &AtomicU64) -> Vec<Alert> {
    documents
        .iter()
        .flat_map(|document| match serde_json::from_slice::<Value>(&document.payload) {
            Ok(event) => process_event(engine, &identity_of(&event, &document.payload), &event),
            Err(error) => {
                warn!(%error, "document ignored: not JSON");
                invalid.fetch_add(1, Ordering::SeqCst);
                Vec::new()
            }
        })
        .collect()
}


pub fn record_of(tenant: &str, alert: Alert) -> AlertRecord {
    AlertRecord {
        id: alert_id(tenant, &alert.rule_id, &alert.event_ids),
        tenant: tenant.to_owned(),
        rule_id: alert.rule_id,
        rule_title: alert.rule_title,
        group: alert.group,
        first_ms: alert.first_ms,
        last_ms: alert.last_ms,
        event_ids: alert.event_ids,
    }
}


/// One batch of one tenant: the engine runs, the alerts (at most `max_alerts`, the excess counted and logged) are committed, and a commit failure restores the windows.
pub fn detect_batch(detector: &Detector, tenant: &str, documents: &[Document]) -> Result<(), BoxError> {
    let engine = engine_for(detector, tenant)?;
    let saved = snapshot(&engine);
    let alerts = collect_alerts(&engine, documents, &detector.invalid);
    let total = alerts.len();
    let records: Vec<AlertRecord> = alerts
        .into_iter()
        .take(detector.max_alerts)
        .map(|alert| record_of(tenant, alert))
        .collect();
    let refused = total - records.len();
    match (detector.commit)(&detector.store, tenant, &records) {
        Ok(stored) => {
            let cap = detector.max_alerts;
            if refused > 0 {
                warn!(tenant, refused, cap, "alerts over the per-batch cap were refused");
            }
            detector.refused.fetch_add(refused as u64, Ordering::SeqCst);
            detector.dirty.store(true, Ordering::SeqCst);
            debug!(tenant, stored, "batch committed");
            Ok(())
        }
        Err(error) => {
            restore_state(&engine, saved);
            Err(BoxError::from(error))
        }
    }
}


/// The batcher's sink: documents in, alerts committed or an error that leaves the batch unacknowledged.
pub fn detection_sink(detector: Arc<Detector>) -> Box<SinkFn> {
    Box::new(move |tenant, documents| detect_batch(&detector, tenant, documents))
}


/// Writes every tenant's windows to its checkpoint file (temporary file, fsync, rename); returns how many tenants were saved.
pub fn save_all(detector: &Detector) -> Result<usize, DetectionError> {
    let engines: Vec<(String, Arc<Engine>)> = detector
        .engines
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .iter()
        .map(|(tenant, engine)| (tenant.clone(), Arc::clone(engine)))
        .collect();
    engines
        .iter()
        .try_for_each(|(tenant, engine)| save_checkpoint(&checkpoint_path(&detector.checkpoint_dir, tenant), &snapshot(engine)))?;
    Ok(engines.len())
}


/// Saves when a batch committed since the last save; a failed save is logged and tried again at the next call.
pub fn checkpoint_if_dirty(detector: &Detector) {
    if detector.dirty.swap(false, Ordering::SeqCst) {
        if let Err(error) = save_all(detector) {
            warn!(%error, "checkpoint not saved, will retry");
            detector.dirty.store(true, Ordering::SeqCst);
        }
    }
}
