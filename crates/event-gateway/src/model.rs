use async_nats::jetstream::Context;
use async_nats::Client;
use core_config::reload::ReloadEngine;
use serde::Deserialize;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio::time::Instant;


pub const MODULE: &str = "event-gateway";


pub const SECTION: &str = "gateway";


pub const RELOAD_REQUEST_ID: &str = "gateway-reload";


pub const AUDIT_TENANT: &str = "platform";


pub const DEFAULT_NATS_URL: &str = "tls://127.0.0.1:4222";


pub const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 5000;


pub const DEFAULT_PUBLISH_TIMEOUT_MS: u64 = 5000;


pub const DEFAULT_PING_INTERVAL_MS: u64 = 10_000;


pub const DEFAULT_MAX_IN_FLIGHT_BATCHES: usize = 64;


pub const DEFAULT_MAX_EVENTS_PER_BATCH: usize = 1000;


pub const DEFAULT_BACKOFF_INITIAL_MS: u64 = 500;


pub const DEFAULT_BACKOFF_MAX_MS: u64 = 30_000;


/// Period of the log line summarising the refused batches.
pub const SUMMARY_INTERVAL_MS: u64 = 60_000;


pub const LIMIT_MS: u64 = 600_000;


pub const LIMIT_COUNT: usize = 100_000;


/// Every setting is bounded by `validate_settings`; the defaults pass it. Secrets are files, never values.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct GatewaySettings {
    pub nats_url: String,
    pub nats_tls_first: bool,
    pub nats_ca_file: Option<PathBuf>,
    pub nats_credentials_file: Option<PathBuf>,
    pub nats_user: Option<String>,
    pub nats_password_file: Option<PathBuf>,
    pub connect_timeout_ms: u64,
    pub publish_timeout_ms: u64,
    pub ping_interval_ms: u64,
    pub max_in_flight_batches: usize,
    pub max_events_per_batch: usize,
    pub backoff_initial_ms: u64,
    pub backoff_max_ms: u64,
}


impl Default for GatewaySettings {
    fn default() -> Self {
        Self {
            nats_url: DEFAULT_NATS_URL.to_owned(),
            nats_tls_first: false,
            nats_ca_file: None,
            nats_credentials_file: None,
            nats_user: None,
            nats_password_file: None,
            connect_timeout_ms: DEFAULT_CONNECT_TIMEOUT_MS,
            publish_timeout_ms: DEFAULT_PUBLISH_TIMEOUT_MS,
            ping_interval_ms: DEFAULT_PING_INTERVAL_MS,
            max_in_flight_batches: DEFAULT_MAX_IN_FLIGHT_BATCHES,
            max_events_per_batch: DEFAULT_MAX_EVENTS_PER_BATCH,
            backoff_initial_ms: DEFAULT_BACKOFF_INITIAL_MS,
            backoff_max_ms: DEFAULT_BACKOFF_MAX_MS,
        }
    }
}


/// One live NATS connection with the settings snapshot it was built from.
pub struct Session {
    pub client: Client,
    pub jetstream: Context,
    pub dropped: Arc<AtomicBool>,
    pub settings: Arc<GatewaySettings>,
}


/// The lazily opened session and the backoff after failed connects.
#[derive(Default)]
pub struct Link {
    pub session: Option<Session>,
    pub failures: u32,
    pub retry_at: Option<Instant>,
}


pub struct Gateway {
    pub settings: Arc<ReloadEngine<GatewaySettings>>,
    pub link: Mutex<Link>,
    pub in_flight: Arc<AtomicUsize>,
    pub refusals: Arc<Refusals>,
}


/// Batches refused since the start, one counter per refusal kind.
#[derive(Default)]
pub struct Refusals {
    pub not_an_object: AtomicU64,
    pub payload_too_large: AtomicU64,
    pub too_many_events: AtomicU64,
    pub invalid_identity: AtomicU64,
    pub busy: AtomicU64,
    pub backing_off: AtomicU64,
}


/// A read of `Refusals` at one moment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RefusalCounts {
    pub not_an_object: u64,
    pub payload_too_large: u64,
    pub too_many_events: u64,
    pub invalid_identity: u64,
    pub busy: u64,
    pub backing_off: u64,
}


/// The periodic summary task; `Drop` stops it.
pub struct SummaryTask {
    pub handle: JoinHandle<()>,
}


impl Drop for SummaryTask {
    fn drop(&mut self) {
        self.handle.abort();
    }
}


/// Holds one in-flight place; `Drop` gives it back on every exit path.
pub struct Slot {
    pub counter: Arc<AtomicUsize>,
}


impl Drop for Slot {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::SeqCst);
    }
}


/// What the gateway needs besides the server file: where its settings and its audit log are.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GatewayFile {
    pub settings_file: PathBuf,
    pub audit_file: PathBuf,
}
