use crate::detect::{checkpoint_if_dirty, detection_sink, new_detector, save_all};
use crate::error::DetectionError;
use crate::model::{
    AlertStore, CommitPolicy, Detector, SinkKind, AUDIT_TENANT, INGEST_REQUEST_ID, MAX_ALERTS_PER_BATCH, MAX_COMMIT_ATTEMPTS, MAX_ROTATED_FILES,
    MAX_STORED_ALERTS, MAX_TENANTS, MODULE, PG_REQUEST_ID, RULES_REQUEST_ID,
};
use crate::pg::{open_pg_store, system_micros};
use crate::settings::{fixed_paths, load_detection_file, open_ingest, open_pg_engine, open_rules_engine};
use crate::store::open_alert_store;
use crate::types::{AlertSinkFn, ClockFn, SharedStopFn, SleepFn};
use agent_channel::app::{alerting_audit, debounce, keep_signals, reload_context, shared_log_audit};
use core_audit::log::open_file_log;
use core_config::reload::ReloadEngine;
use core_config::watch::watch_files;
use siem_ingest::batcher::{new_batcher, real_sleep, system_clock};
use siem_ingest::model::{LoopReport, Pipeline, Wiring};
use siem_ingest::nats::nats_wiring;
use siem_ingest::pipeline::{new_pipeline, run_loop};
use siem_ingest::settings::IngestSettings;
use siem_ingest::types::StopFn;
use std::fs::create_dir_all;
use std::path::{Path, PathBuf};
use std::sync::Arc;


/// The batcher over the detection sink; the clock and the sleep are function pointers so tests can stand in for them.
pub fn detection_pipeline(
    settings: Arc<ReloadEngine<IngestSettings>>,
    detector: Arc<Detector>,
    wiring: Wiring,
    (clock, sleep): (ClockFn, SleepFn),
) -> Pipeline {
    new_pipeline(new_batcher(settings, detection_sink(detector), Box::new(clock), Box::new(sleep)), wiring)
}


/// Runs the bus loop until `stop`, saving the windows after every cycle that committed a batch (so after its acknowledgement) and once at the end.
pub fn run_detection(pipeline: &mut Pipeline, detector: Arc<Detector>, stop: Box<StopFn>) -> Result<LoopReport, DetectionError> {
    let saver = Arc::clone(&detector);
    let checkpointing = move || {
        checkpoint_if_dirty(&saver);
        stop()
    };
    let summary = run_loop(pipeline, &checkpointing);
    save_all(&detector)?;
    Ok(summary)
}


/// The whole service: audit log, settings and rule engines (watched files and `SIGHUP`), alerts file, bus wiring, then the loop.
pub fn run_service(path: &Path, stop: Box<SharedStopFn>, commit: AlertSinkFn) -> Result<LoopReport, DetectionError> {
    let file = load_detection_file(path)?;
    let log = Arc::new(open_file_log(&file.audit_file)?);
    let ingest = Arc::new(open_ingest(
        path.to_path_buf(),
        fixed_paths(&file),
        alerting_audit(shared_log_audit(&log)),
        reload_context(path, MODULE, AUDIT_TENANT, INGEST_REQUEST_ID),
    )?);
    let rules = Arc::new(open_rules_engine(
        path.to_path_buf(),
        fixed_paths(&file),
        alerting_audit(shared_log_audit(&log)),
        reload_context(path, MODULE, AUDIT_TENANT, RULES_REQUEST_ID),
    )?);
    create_dir_all(&file.checkpoint_dir)?;
    let pg_engine = match file.sink {
        SinkKind::File => None,
        SinkKind::Postgres => Some(Arc::new(open_pg_engine(
            path.to_path_buf(),
            fixed_paths(&file),
            alerting_audit(shared_log_audit(&log)),
            reload_context(path, MODULE, AUDIT_TENANT, PG_REQUEST_ID),
        )?)),
    };
    let store = Arc::new(match &pg_engine {
        None => open_alert_store(&file.alerts_file, MAX_STORED_ALERTS, MAX_ROTATED_FILES)?,
        Some(engine) => AlertStore::Postgres(open_pg_store(Arc::clone(engine), system_micros)?),
    });
    let wiring = nats_wiring(Arc::clone(&ingest))?;
    let shared_stop: Arc<SharedStopFn> = Arc::from(stop);
    let policy = CommitPolicy {
        ingest: Arc::clone(&ingest),
        progress: Arc::clone(&wiring.progress),
        stop: Arc::clone(&shared_stop),
        sleep: real_sleep,
        max_attempts: MAX_COMMIT_ATTEMPTS,
    };
    let detector = Arc::new(new_detector(
        Arc::clone(&rules),
        store,
        commit,
        (MAX_ALERTS_PER_BATCH, MAX_TENANTS),
        file.checkpoint_dir.clone(),
        policy,
    ));
    let rule_watch: Vec<PathBuf> = file
        .rule_files
        .iter()
        .cloned()
        .chain([file.mapping_file.clone(), path.to_path_buf()])
        .collect();
    let _ingest_watch = watch_files(Arc::clone(&ingest), &[path.to_path_buf()], debounce())?;
    let _rules_watch = watch_files(Arc::clone(&rules), &rule_watch, debounce())?;
    let pg_watch = pg_engine
        .as_ref()
        .map(|engine| watch_files(Arc::clone(engine), &[path.to_path_buf()], debounce()))
        .transpose();
    let _pg_watch = pg_watch?;
    let _pg_signals = pg_engine.map(keep_signals).transpose()?;
    let _ingest_signals = keep_signals(Arc::clone(&ingest))?;
    let _rules_signals = keep_signals(rules)?;
    let mut pipeline = detection_pipeline(ingest, Arc::clone(&detector), wiring, (system_clock, real_sleep));
    run_detection(&mut pipeline, detector, Box::new(move || (*shared_stop)()))
}
