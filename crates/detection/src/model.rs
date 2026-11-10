use crate::types::{AlertSinkFn, AlertSyncFn, AlertWriter, EngineMap, KindCounts, MicrosFn, RotateFn, SharedStopFn, SleepFn};
use core_config::reload::ReloadEngine;
use core_pg::settings::PgSettings;
use serde::{Deserialize, Serialize};
use siem_ingest::settings::IngestSettings;
use siem_ingest::types::ProgressFn;
use std::collections::{BTreeMap, HashSet};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Arc, Mutex};
use stream_correlation::level::Level;
use stream_correlation::ruleset::RuleSet;
use tokio::runtime::Runtime;
use tokio_postgres::Client;


pub const MODULE: &str = "detection";


pub const AUDIT_TENANT: &str = "all";


pub const INGEST_REQUEST_ID: &str = "detection-ingest-reload";


pub const PG_REQUEST_ID: &str = "detection-postgres-reload";


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


pub const MICROS_PER_SECOND: u64 = 1_000_000;


pub const NANOS_PER_MILLI: i128 = 1_000_000;


/// 0000-01-01T00:00:00Z and 9999-12-31T23:59:59.999Z in Unix milliseconds: the range of an RFC 3339 year.
pub const MIN_EVENT_MS: i64 = -62_167_219_200_000;


pub const MAX_EVENT_MS: i64 = 253_402_300_799_999;


pub const HOST_FIELD: &str = "host.name";


pub const USER_FIELD: &str = "user.name";


pub const REPLACEMENT: char = '\u{fffd}';


/// One alert as stored: the id is the idempotence key, the tenant is the subject's.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AlertRecord {
    pub id: String,
    pub tenant: String,
    pub rule_id: String,
    pub rule_title: String,
    pub level: Level,
    pub group: BTreeMap<String, String>,
    pub first_ms: i64,
    pub last_ms: i64,
    pub event_ids: Vec<String>,
}


/// Where the alerts go: a local file or the PostgreSQL store.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SinkKind {
    #[default]
    File,
    Postgres,
}


/// The service file: the output paths and the sink are read at start, the `ingest` and `postgres` sections and the rule files on every reload.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectionFile {
    pub audit_file: PathBuf,
    pub checkpoint_dir: PathBuf,
    pub alerts_file: PathBuf,
    pub mapping_file: PathBuf,
    pub rule_files: Vec<PathBuf>,
    #[serde(default)]
    pub sink: SinkKind,
    #[serde(default)]
    pub postgres: Option<PgSettings>,
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
    pub sink: SinkKind,
}


/// The PostgreSQL sink: its own runtime, the settings read afresh at every connect, the connection kept between batches, the clock of `created`.
pub struct PgStore {
    pub runtime: Runtime,
    pub settings: Arc<ReloadEngine<PgSettings>>,
    pub link: Mutex<Option<Client>>,
    pub clock: MicrosFn,
}


pub enum AlertStore {
    File(Mutex<FileStore>),
    Postgres(PgStore),
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
    pub permanent: Mutex<KindCounts>,
    pub late: AtomicU64,
    pub dirty: AtomicBool,
}
