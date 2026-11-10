use crate::error::{DetectionError, SinkError};
use crate::id::event_identity;
use crate::model::{AlertRecord, AlertStore, CommitPolicy, Detector, ACK_WAIT_DIVISOR};
use crate::types::{AlertSinkFn, EngineMap, KindCounts};
use alerts::error::StoreError;
use alerts::id::alert_id;
use core_config::reload::{current_config, ReloadEngine};
use core_config::types::BoxError;
use core_pg::error::PgError;
use core_pg::scope::tenant_scope;
use serde_json::Value;
use siem_ingest::batcher::backoff_delay;
use siem_ingest::model::Document;
use siem_ingest::types::SinkFn;
use std::error::Error;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};
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
    retry: CommitPolicy,
) -> Detector {
    Detector {
        retry,
        late: AtomicU64::new(0),
        rules,
        engines: Mutex::new(EngineMap::new()),
        store,
        commit,
        max_alerts: limits.0,
        max_tenants: limits.1,
        checkpoint_dir,
        refused: AtomicU64::new(0),
        invalid: AtomicU64::new(0),
        permanent: Mutex::new(KindCounts::new()),
        dirty: AtomicBool::new(false),
    }
}


/// The tenant names a file and scopes the store, so it is exactly what core-pg's `tenant_scope` accepts.
pub fn valid_tenant(tenant: &str) -> bool {
    tenant_scope(tenant).is_ok()
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
        let had_checkpoint = restored.is_some();
        debug!(had_checkpoint, "tenant engine started, no checkpoint means a first start");
        let engine = Arc::new(new_engine(Arc::clone(&detector.rules), restored.unwrap_or_else(State::default)));
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
        level: alert.level,
        group: alert.group,
        first_ms: alert.first_ms,
        last_ms: alert.last_ms,
        event_ids: alert.event_ids,
    }
}


pub fn late_events(engine: &Engine) -> u64 {
    engine.state.lock().unwrap_or_else(PoisonError::into_inner).counters.late
}


/// Tells the bus the batch is still being worked on; a failure is logged, the retry goes on.
pub fn report_progress(detector: &Detector) {
    if let Err(error) = (detector.retry.progress)() {
        warn!(%error, "in-progress acknowledgement failed");
    }
}


/// A refusal the store would repeat for the same records, however often it is retried (a bound, an identity, a time or a tenant); only a connection, a timeout or an answer after SQL was sent can heal.
pub fn is_permanent(error: &SinkError) -> bool {
    match error {
        SinkError::EventIdTooLong { .. }
        | SinkError::EventTimeRange(_)
        | SinkError::EventTimeFormat(_)
        | SinkError::TenantMismatch
        | SinkError::Database(PgError::InvalidTenant)
        | SinkError::Serialize(_) => true,
        SinkError::Store(inner) => !matches!(
            inner,
            StoreError::Pg(_) | StoreError::BadRow { .. } | StoreError::BadNumber { .. } | StoreError::BadEvents(_)
        ),
        _ => false,
    }
}


/// Counts the refused records under the kind of the refusal (the cause's fixed text, never alert or event content) and warns with the totals.
pub fn refuse_permanent(detector: &Detector, refused: usize, error: &SinkError) {
    let kind = error.source().map_or_else(|| error.to_string(), ToString::to_string);
    let total = {
        let mut counts = detector.permanent.lock().unwrap_or_else(PoisonError::into_inner);
        let count = counts.entry(kind.clone()).or_insert(0);
        *count += refused as u64;
        *count
    };
    warn!(kind, refused, total, "alerts refused for good");
}


/// Commits the batch, retrying a transient failure in place; a permanent refusal drops only the records it concerns.
pub fn commit_in_place(detector: &Detector, tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    match retry_in_place(detector, tenant, records) {
        Err(error) if is_permanent(&error) => commit_each(detector, tenant, records),
        other => other,
    }
}


/// Commits the records one by one after a permanent refusal of the batch: the refused ones are counted per kind, the others are stored.
pub fn commit_each(detector: &Detector, tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    records
        .iter()
        .try_fold(0, |stored, record| match retry_in_place(detector, tenant, std::slice::from_ref(record)) {
            Ok(fresh) => Ok(stored + fresh),
            Err(error) if is_permanent(&error) => {
                refuse_permanent(detector, 1, &error);
                Ok(stored)
            }
            Err(error) => Err(error),
        })
}


/// Retries a transient failure in place (nothing later is fetched, so the order survives a store failure) until it works, the service stops or `max_attempts`; a permanent refusal is returned at once.
pub fn retry_in_place(detector: &Detector, tenant: &str, records: &[AlertRecord]) -> Result<usize, SinkError> {
    let policy = &detector.retry;
    let settings = current_config(&policy.ingest);
    let half_wait = Duration::from_millis(settings.nats_ack_wait_ms / ACK_WAIT_DIVISOR);
    let outcome = (0..policy.max_attempts).try_fold(Duration::ZERO, |waited, attempt| {
        let started = Instant::now();
        match (detector.commit)(&detector.store, tenant, records) {
            Ok(stored) => Err(Ok(stored)),
            Err(error) if is_permanent(&error) => Err(Err(error)),
            Err(error) if (policy.stop)() || attempt + 1 == policy.max_attempts => Err(Err(error)),
            Err(error) => {
                let delay = backoff_delay(&settings, attempt);
                let delay_ms = delay.as_millis() as u64;
                warn!(attempt, %error, delay_ms, "store refused the alerts, retrying in place");
                (policy.sleep)(delay);
                let total = waited + delay + started.elapsed();
                if total >= half_wait {
                    report_progress(detector);
                    Ok(Duration::ZERO)
                } else {
                    Ok(total)
                }
            }
        }
    });
    outcome.map_or_else(|done| done, |_| Err(SinkError::Exhausted))
}


/// One batch of one tenant: the engine runs, the alerts (at most `max_alerts`, the excess counted and logged) are committed, and a commit failure restores the windows.
pub fn detect_batch(detector: &Detector, tenant: &str, documents: &[Document]) -> Result<(), BoxError> {
    if valid_tenant(tenant) {
        detect_valid_batch(detector, tenant, documents)
    } else {
        refuse_tenant(detector, documents.len());
        Ok(())
    }
}


/// A tenant core-pg refuses is refused again on every redelivery: its batch is counted per kind and acknowledged, the tenant text is never logged.
pub fn refuse_tenant(detector: &Detector, events: usize) {
    refuse_permanent(detector, events, &SinkError::Database(PgError::InvalidTenant));
}


pub fn detect_valid_batch(detector: &Detector, tenant: &str, documents: &[Document]) -> Result<(), BoxError> {
    let engine = engine_for(detector, tenant)?;
    let saved = snapshot(&engine);
    let late_before = saved.counters.late;
    let alerts = collect_alerts(&engine, documents, &detector.invalid);
    let total = alerts.len();
    let records: Vec<AlertRecord> = alerts
        .into_iter()
        .take(detector.max_alerts)
        .map(|alert| record_of(tenant, alert))
        .collect();
    let refused = total - records.len();
    match commit_in_place(detector, tenant, &records) {
        Ok(stored) => {
            let cap = detector.max_alerts;
            let late = late_events(&engine).saturating_sub(late_before);
            if refused > 0 {
                warn!(tenant, refused, cap, "alerts over the per-batch cap were refused");
            }
            if late > 0 {
                warn!(tenant, late, "events dropped as later than the allowed lateness");
            }
            detector.late.fetch_add(late, Ordering::SeqCst);
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
