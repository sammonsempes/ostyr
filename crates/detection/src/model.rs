use crate::types::{AlertSinkFn, AlertSyncFn, AlertWriter, EngineMap, RotateFn, SharedStopFn, SleepFn};
use core_config::reload::ReloadEngine;
use serde::{Deserialize, Serialize};
use siem_ingest::settings::IngestSettings;
use siem_ingest::types::ProgressFn;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use stream_correlation::ruleset::RuleSet;


pub const MODULE: &str = "detection";


pub const AUDIT_TENANT: &str = "all";


pub const INGEST_REQUEST_ID: &str = "detection-ingest-reload";


pub const RULES_REQUEST_ID: &str = "detection-rules-reload";


pub const MAX_ALERTS_PER_BATCH: usize = 1000;


pub const MAX_TENANTS: usize = 1024;


pub const MAX_ALERT_LINE_BYTES: usize = 1_048_576;


pub const MAX_STORED_ALERTS: usize = 10_000_000;


pub const MAX_ROTATED_FILES: usize = 4;


pub const MAX_COMMIT_ATTEMPTS: u32 = 100_000;


pub const ACK_WAIT_DIVISOR: u64 = 2;


pub const MAX_FIELD_CHARS: usize = 1024;


pub const MAX_GROUP_FIELDS: usize = 16;


pub const MAX_STORED_EVENT_IDS: usize = 100;


/// One alert as stored: the id is the idempotence key, the tenant is the subject's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: String,
    pub tenant: String,
    pub rule_id: String,
    pub rule_title: String,
    pub group: BTreeMap<String, String>,
    pub first_ms: i64,
    pub last_ms: i64,
    pub event_ids: Vec<String>,
}


/// The service file: the output paths are read at start, the `ingest` section and the rule files on every reload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionFile {
    pub audit_file: PathBuf,
    pub checkpoint_dir: PathBuf,
    pub alerts_file: PathBuf,
    pub mapping_file: PathBuf,
    pub rule_files: Vec<PathBuf>,
    #[serde(default)]
    pub ingest: IngestSettings,
}


/// The alerts file as a writer plus the ids it holds on disk; `damaged` remembers a failed write; `rotate` starts a new file once `max_stored` ids are held.
pub struct FileStore {
    pub writer: AlertWriter,
    pub sync: AlertSyncFn,
    pub rotate: RotateFn,
    pub seen: HashSet<String>,
    pub damaged: bool,
    pub max_stored: usize,
}


/// How a failed commit is retried in place: the ingest settings give the backoff and the ack wait, `progress` keeps the batch from being redelivered.
pub struct CommitPolicy {
    pub ingest: Arc<ReloadEngine<IngestSettings>>,
    pub progress: Arc<ProgressFn>,
    pub stop: Arc<SharedStopFn>,
    pub sleep: SleepFn,
    pub max_attempts: u32,
}


/// The settings read at start only: a live change of one of them is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FixedPaths {
    pub audit_file: PathBuf,
    pub checkpoint_dir: PathBuf,
    pub alerts_file: PathBuf,
}


pub struct AlertStore {
    pub inner: Mutex<FileStore>,
}


/// One engine per tenant over the shared rule set, so windows never mix tenants; `commit` stores the alerts of a batch.
pub struct Detector {
    pub rules: Arc<ReloadEngine<RuleSet>>,
    pub engines: Mutex<EngineMap>,
    pub store: Arc<AlertStore>,
    pub commit: AlertSinkFn,
    pub max_alerts: usize,
    pub max_tenants: usize,
    pub checkpoint_dir: PathBuf,
    pub retry: CommitPolicy,
    pub refused: AtomicU64,
    pub invalid: AtomicU64,
    pub late: AtomicU64,
    pub dirty: AtomicBool,
}
