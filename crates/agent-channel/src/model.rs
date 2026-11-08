use crate::error::ChannelError;
use crate::proto::EventBatch;
use crate::types::{AuditSink, CommandSource, EventSink, SharedSettings};
use agent_command::model::Command;
use secrecy::SecretString;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tokio::sync::{oneshot, Semaphore};


pub const SETTINGS_SECTION: &str = "channel_settings";


pub const MAX_TOTAL_CONNECTIONS_LIMIT: usize = 1_000_000;


pub const IDENTITY_URI_PREFIX: &str = "urn:ostyr:agent:";


pub const MAX_IDENTITY_COMPONENT_LENGTH: usize = 64;


pub const CONNECT_TIMEOUT_SECONDS: u64 = 10;


pub const ALPN_H2: &[u8] = b"h2";


pub const HEARTBEAT_PATH: &str = "/ostyr.agent.v1.Heartbeat/Beat";


pub const EVENTS_PATH: &str = "/ostyr.agent.v1.Events/Push";


pub const SUBSCRIBE_PATH: &str = "/ostyr.agent.v1.Commands/Subscribe";


pub const REPORT_PATH: &str = "/ostyr.agent.v1.Commands/Report";


pub const DEFAULT_HEARTBEAT_INTERVAL_SECONDS: u64 = 30;


/// Reason reported when the executor cannot take an accepted command; its sequence is consumed, so the signer issues a new one.
pub const EXECUTOR_BUSY_REASON: &str = "executor busy, command not executed";


pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1_048_576;


pub const DEFAULT_MAX_STREAMS_PER_AGENT: usize = 4;


pub const DEFAULT_MAX_REQUESTS_PER_WINDOW: u32 = 200;


pub const DEFAULT_RATE_WINDOW_SECONDS: u64 = 1;


pub const DEFAULT_MAX_CONNECTIONS_PER_AGENT: usize = 4;


pub const DEFAULT_MAX_STREAMS_PER_CONNECTION: u32 = 8;


pub const DEFAULT_MAX_INFLIGHT_PER_AGENT: usize = 8;


pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;


pub const DEFAULT_MAX_TOTAL_CONNECTIONS: usize = 1_024;


/// Connections still in their TLS handshake: beyond this the oldest one is dropped to make room, so stalled peers cannot keep agents out.
pub const DEFAULT_MAX_PENDING_HANDSHAKES: usize = 256;


/// Pending handshakes one source may hold; further connections from it are refused, so one host cannot evict the agents of the others.
pub const DEFAULT_MAX_PENDING_HANDSHAKES_PER_SOURCE: usize = 16;


/// An IPv6 source is folded to its /64: the host bits are cleared.
pub const IPV6_HOST_BITS: u32 = 64;


/// Under the five minutes of the specification, so an operator sees a silent agent before the contractual delay.
pub const DEFAULT_SILENCE_THRESHOLD_SECONDS: u64 = 150;


pub const DEFAULT_SILENCE_CHECK_INTERVAL_SECONDS: u64 = 10;


/// A peer that has not finished its TLS handshake after this long is dropped, so a stalled peer cannot hold a task.
pub const HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;


/// One delivery attempt (dial, stream, acknowledgements) is cut after this long, so a server holding the stream open cannot hang the agent.
pub const ATTEMPT_TIMEOUT_SECONDS: u64 = 60;


/// A unary call (`heartbeat`, `report_command`) is cut after this long, so a live but silent server cannot hang the agent.
pub const UNARY_TIMEOUT_SECONDS: u64 = 30;


/// Acknowledgements for batches not pending that one attempt tolerates before it stops reading.
pub const MAX_IGNORED_ACKS: usize = 8;


/// Refusal verdicts a command run keeps for its caller; later ones are counted and logged only.
pub const MAX_KEPT_REFUSALS: usize = 64;


/// Absolute bound of the acknowledgement read loop, whatever the number of pending batches.
pub const MAX_ACK_READS: usize = 4_096;


/// HTTP/2 keepalive ping interval: a server host that died without a FIN is detected after this plus the timeout.
pub const KEEPALIVE_INTERVAL_SECONDS: u64 = 10;


pub const KEEPALIVE_TIMEOUT_SECONDS: u64 = 10;


/// Server HTTP/2 keepalive ping interval, sent while idle too: an agent that vanished without a FIN is dropped after this plus the timeout.
pub const SERVER_KEEPALIVE_INTERVAL_SECONDS: u64 = 20;


pub const SERVER_KEEPALIVE_TIMEOUT_SECONDS: u64 = 10;


pub const BACKOFF_INITIAL_MILLIS: u64 = 500;


/// The reconnection delay never exceeds this, jitter included.
pub const BACKOFF_MAX_MILLIS: u64 = 30_000;


/// Consecutive failed attempts, without any batch acknowledged, before a delivery gives up.
pub const MAX_RECONNECT_ATTEMPTS: u32 = 10;


/// Each attempt waits this many times longer than the previous one; half of a delay is fixed, the other half is jitter.
pub const BACKOFF_FACTOR: u64 = 2;


/// Largest exponent applied to `BACKOFF_FACTOR`: beyond it the delay is the maximum anyway.
pub const MAX_BACKOFF_SHIFT: u32 = 16;


pub const AUDIT_MODULE: &str = "agent-channel";


pub const AUDIT_ACTOR: &str = "agent-channel";


pub const SILENT_ACTION: &str = "agent.silent";


pub const BACK_ACTION: &str = "agent.back";


/// Agent-supplied text is cut to this many characters before it reaches a log line.
pub const MAX_LOGGED_TEXT_CHARS: usize = 128;


/// Digest bytes shown in a log line, hex-encoded: twice `MAX_LOGGED_TEXT_CHARS` characters.
pub const MAX_LOGGED_DIGEST_BYTES: usize = 64;


pub const TRUNCATION_MARKER: &str = "...[truncated]";


/// Most significant bit of the first serial byte: set means a negative DER integer.
pub const SERIAL_SIGN_BIT: u8 = 0x80;


/// Upper bound between a serial entering the revocation list and the close of that agent connections.
pub const REVOCATION_CLOSE_SECONDS: u64 = 5;


pub const PLACEHOLDER_ENDPOINT: &str = "http://agent-channel.invalid";


/// The agent identity, read from the verified client certificate and from nowhere else.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Identity {
    pub tenant: String,
    pub agent_id: String,
}


/// A private key in PEM form; `Debug` shows no key byte.
#[derive(Debug)]
pub struct PrivateKeyPem {
    pub pem: SecretString,
}


#[derive(Clone, Debug)]
pub struct ServerTlsPaths {
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub agent_ca: PathBuf,
}


#[derive(Clone, Debug)]
pub struct ClientTlsPaths {
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub platform_ca: PathBuf,
}


/// The revocation file as written: certificate serials in hexadecimal.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawRevocationFile {
    pub revoked_serials: Vec<String>,
}


/// Revoked certificate serials, lowercase hexadecimal without leading zeros.
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "RawRevocationFile")]
pub struct Revocations {
    pub serials: BTreeSet<String>,
}


/// Bounds and intervals of the server side, loadable from a configuration file; every field defaults to its `DEFAULT_*` const.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ChannelSettings {
    pub heartbeat_interval_seconds: u64,
    pub max_message_bytes: usize,
    pub max_streams_per_agent: usize,
    pub max_requests_per_window: u32,
    pub rate_window_seconds: u64,
    pub max_connections_per_agent: usize,
    pub max_streams_per_connection: u32,
    pub max_inflight_per_agent: usize,
    pub request_timeout_seconds: u64,
    pub max_total_connections: usize,
    pub max_pending_handshakes: usize,
    pub max_pending_handshakes_per_source: usize,
    pub silence_threshold_seconds: u64,
    pub silence_check_interval_seconds: u64,
}


impl Default for ChannelSettings {
    fn default() -> Self {
        Self {
            heartbeat_interval_seconds: DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_streams_per_agent: DEFAULT_MAX_STREAMS_PER_AGENT,
            max_requests_per_window: DEFAULT_MAX_REQUESTS_PER_WINDOW,
            rate_window_seconds: DEFAULT_RATE_WINDOW_SECONDS,
            max_connections_per_agent: DEFAULT_MAX_CONNECTIONS_PER_AGENT,
            max_streams_per_connection: DEFAULT_MAX_STREAMS_PER_CONNECTION,
            max_inflight_per_agent: DEFAULT_MAX_INFLIGHT_PER_AGENT,
            request_timeout_seconds: DEFAULT_REQUEST_TIMEOUT_SECONDS,
            max_total_connections: DEFAULT_MAX_TOTAL_CONNECTIONS,
            max_pending_handshakes: DEFAULT_MAX_PENDING_HANDSHAKES,
            max_pending_handshakes_per_source: DEFAULT_MAX_PENDING_HANDSHAKES_PER_SOURCE,
            silence_threshold_seconds: DEFAULT_SILENCE_THRESHOLD_SECONDS,
            silence_check_interval_seconds: DEFAULT_SILENCE_CHECK_INTERVAL_SECONDS,
        }
    }
}


/// Refusals and outcomes since the server started.
#[derive(Debug, Default)]
pub struct Counters {
    pub oversized: AtomicU64,
    pub rate_limited: AtomicU64,
    pub stream_limited: AtomicU64,
    pub connection_limited: AtomicU64,
    pub inflight_limited: AtomicU64,
    pub timed_out: AtomicU64,
    pub identity_mismatch: AtomicU64,
    pub events_acknowledged: AtomicU64,
    pub commands_accepted: AtomicU64,
    pub commands_refused: AtomicU64,
    pub connections_capped: AtomicU64,
    pub handshake_timeouts: AtomicU64,
    pub handshakes_evicted: AtomicU64,
    pub handshakes_refused: AtomicU64,
}


/// What one agent currently holds: connections, streams, requests in flight and the requests of the current rate window.
#[derive(Clone, Debug)]
pub struct AgentLoad {
    pub connections: usize,
    pub streams: usize,
    pub inflight: usize,
    pub window_started: Instant,
    pub window_count: u32,
}


/// When an agent last sent a heartbeat and whether its silence was already recorded.
#[derive(Clone, Debug)]
pub struct Presence {
    pub last_beat: Instant,
    pub silent: bool,
}


/// Shared by every connection: bounds, counters, per-agent load, heartbeats and the injected ends (event sink, command source, audit).
pub struct ServerState {
    pub settings: SharedSettings,
    pub counters: Counters,
    pub load: Mutex<HashMap<Identity, AgentLoad>>,
    pub events: EventSink,
    pub commands: CommandSource,
    pub presence: Mutex<HashMap<Identity, Presence>>,
    pub audit: AuditSink,
}


/// The kinds of per-agent slot: an open connection, an open stream, a request being handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    Connection,
    Stream,
    Inflight,
}


/// One slot of an agent; dropping it gives the slot back.
pub struct SlotPermit {
    pub state: Arc<ServerState>,
    pub identity: Identity,
    pub kind: SlotKind,
}


/// Everything a running `Events` stream needs; the permit goes with the stream.
pub struct PushSession {
    pub state: Arc<ServerState>,
    pub identity: Identity,
    pub permit: SlotPermit,
}


/// What the agent decided about one command envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandVerdict {
    pub digest: Vec<u8>,
    pub accepted: bool,
    pub reason: String,
}


/// What `run_connection` receives from `serve`: the cap on authenticated connections and the signal that drops a connection still in its handshake.
#[derive(Debug)]
pub struct Admission {
    pub connections: Arc<Semaphore>,
    pub evicted: oneshot::Receiver<()>,
}


/// A connection still in its TLS handshake: the source it came from and the signal that drops it.
#[derive(Debug)]
pub struct PendingHandshake {
    pub source: IpAddr,
    pub stop: oneshot::Sender<()>,
}


/// Event batches of one delivery: what is still unacknowledged, what was acknowledged, and the failures since the last progress.
#[derive(Debug)]
pub struct Delivery {
    pub pending: Vec<EventBatch>,
    pub acknowledged: Vec<u64>,
    pub failures: u32,
    pub last: Result<(), ChannelError>,
}


/// The verdict on one envelope and, when it was accepted, the command `verify_command` returned.
#[derive(Debug)]
pub struct Judged {
    pub verdict: CommandVerdict,
    pub command: Option<Command>,
}


/// What a command run keeps: the counts of accepted and refused commands and at most `MAX_KEPT_REFUSALS` refusal verdicts.
#[derive(Debug, Default)]
pub struct CommandRun {
    pub refusals: Vec<CommandVerdict>,
    pub accepted: u64,
    pub refused: u64,
}
