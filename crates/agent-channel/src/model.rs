use crate::error::ChannelError;
use crate::proto::{EventBatch, ShellCloseReason, ShellFrame};
use crate::types::{AuditSink, ClockFn, CommandSource, EventSink, NowFn, SharedSettings, ShellSink, ShellSource};
use agent_command::model::Command;
use secrecy::SecretString;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, oneshot, Semaphore};
use tonic::Status;


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


pub const SHELL_PATH: &str = "/ostyr.agent.v1.Shell/Attach";


/// Shell streams one agent may hold, apart from the `Stream` and `Inflight` slots.
pub const MAX_SHELL_STREAMS_PER_AGENT: usize = 1;


/// Largest `Data` payload of a shell frame, equal to the remote-shell recording frame bound (pinned by a test).
pub const MAX_SHELL_FRAME_BYTES: usize = 65_536;


/// Room for the tag and length of the largest valid shell frame.
pub const MAX_SHELL_FRAME_OVERHEAD: usize = 16;


/// Decoding bound of the shell route: the encoded size of the largest valid frame.
pub const MAX_SHELL_MESSAGE_BYTES: usize = MAX_SHELL_FRAME_BYTES + MAX_SHELL_FRAME_OVERHEAD;


/// Largest terminal width and height in cells.
pub const MAX_TERMINAL_CELLS: u32 = 1_000;


/// From the stream open to the `Open` frame; not above the request timeout, which also cuts the open.
pub const SHELL_OPEN_SECONDS: u64 = 10;


/// Inbound silence after which a shell stream is dead.
pub const SHELL_DEAD_SECONDS: u64 = 60;


/// Longest wait on the injected shell sink.
pub const SHELL_SINK_SECONDS: u64 = 10;


/// Longest wait to hand one item to an agent that does not read.
pub const SHELL_SEND_SECONDS: u64 = 10;


/// Items queued toward the agent.
pub const SHELL_OUTBOUND_CAPACITY: usize = 8;


/// Pending and active shell sessions of the whole server.
pub const MAX_SHELL_SESSIONS: usize = 64;


pub const SHELL_RATE_WINDOW_SECONDS: u64 = 1;


pub const MAX_SHELL_FRAMES_PER_SECOND: u32 = 1_000;


/// Encoded bytes of one session; with the frame overhead it stays under the remote-shell recording bound (pinned by a test).
pub const MAX_SHELL_BYTES_PER_SESSION: u64 = 200_000_000;


/// Frames of one session, keepalives included.
pub const MAX_SHELL_FRAMES_PER_SESSION: u64 = 1_000_000;


pub const DEFAULT_HEARTBEAT_INTERVAL_SECONDS: u64 = 30;


/// Reason reported when the executor cannot take an accepted command; its sequence is consumed, so the signer issues a new one.
pub const EXECUTOR_BUSY_REASON: &str = "executor busy, command not executed";


pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1_048_576;


/// Highest `max_message_bytes` a setting may take: the events file of the example sink bounds its lines from it.
pub const MAX_MESSAGE_BYTES_LIMIT: usize = 4 * DEFAULT_MAX_MESSAGE_BYTES;


pub const DEFAULT_MAX_STREAMS_PER_AGENT: usize = 4;


pub const DEFAULT_MAX_REQUESTS_PER_WINDOW: u32 = 200;


pub const DEFAULT_RATE_WINDOW_SECONDS: u64 = 1;


pub const DEFAULT_MAX_CONNECTIONS_PER_AGENT: usize = 4;


pub const DEFAULT_MAX_STREAMS_PER_CONNECTION: u32 = 8;


pub const DEFAULT_MAX_INFLIGHT_PER_AGENT: usize = 8;


pub const DEFAULT_REQUEST_TIMEOUT_SECONDS: u64 = 30;


/// From TLS completion to the first HTTP/2 request: a peer that sends nothing, or only the preface, is dropped after this long.
pub const DEFAULT_FIRST_REQUEST_TIMEOUT_SECONDS: u64 = 10;


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


/// Default of `handshake_timeout_seconds`: a peer that has not finished its TLS handshake after this long is dropped.
pub const DEFAULT_HANDSHAKE_TIMEOUT_SECONDS: u64 = 10;


/// Largest accepted `handshake_timeout_seconds`, so a setting cannot let a stalled peer hold a task for long.
pub const MAX_HANDSHAKE_TIMEOUT_SECONDS: u64 = 60;


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


/// TCP keepalive on accepted sockets: idle time before the first probe, probe interval and probes, so a silent peer is dropped after 20 + 5 * 3 = 35 s.
pub const TCP_KEEPALIVE_IDLE_SECONDS: u64 = 20;


pub const TCP_KEEPALIVE_INTERVAL_SECONDS: u64 = 5;


pub const TCP_KEEPALIVE_RETRIES: u32 = 3;


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
    pub handshake_timeout_seconds: u64,
    pub first_request_timeout_seconds: u64,
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
            handshake_timeout_seconds: DEFAULT_HANDSHAKE_TIMEOUT_SECONDS,
            first_request_timeout_seconds: DEFAULT_FIRST_REQUEST_TIMEOUT_SECONDS,
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
    pub first_request_timeouts: AtomicU64,
    pub handshakes_evicted: AtomicU64,
    pub handshakes_refused: AtomicU64,
    pub shell_unexpected: AtomicU64,
    pub shell_limited: AtomicU64,
    pub shell_open_timeouts: AtomicU64,
    pub shell_malformed: AtomicU64,
    pub shell_gate_refused: AtomicU64,
    pub shell_opened: AtomicU64,
    pub shell_budget: AtomicU64,
    pub shell_dead: AtomicU64,
    pub shell_sink_timeouts: AtomicU64,
    pub shell_sink_failed: AtomicU64,
    pub shell_send_timeouts: AtomicU64,
    pub shell_lifetime: AtomicU64,
}


/// What one agent currently holds: connections, streams, requests in flight and the requests of the current rate window.
#[derive(Clone, Debug)]
pub struct AgentLoad {
    pub connections: usize,
    pub streams: usize,
    pub inflight: usize,
    pub shells: usize,
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
    pub now: Box<NowFn>,
}


/// The kinds of per-agent slot: an open connection, an open stream, a request being handled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SlotKind {
    Connection,
    Stream,
    Inflight,
    Shell,
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
    pub capacity: usize,
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
    pub rejected: Vec<EventBatch>,
    pub failures: u32,
    pub last: Result<(), ChannelError>,
}


/// What a finished delivery settled: the acknowledged sequences and the batches the server refused as too large.
#[derive(Debug)]
pub struct Delivered {
    pub acknowledged: Vec<u64>,
    pub rejected: Vec<EventBatch>,
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


/// Why an agent closed its shell: the only reasons an agent may claim.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentCloseReason {
    Exited,
    AgentError,
}


/// How a shell stream ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShellEnd {
    AgentClosed(AgentCloseReason),
    PlatformClosed,
    Dead,
    Lifetime,
    Budget,
    Malformed,
    SinkTimeout,
    SinkFailed,
    SendTimeout,
    Dropped,
    Transport,
}


/// What the server hands to the injected shell sink: agent output, a keepalive, the end of the stream.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellSinkEvent {
    Output(Vec<u8>),
    Tick,
    Ended(ShellEnd),
}


/// What the injected shell source gives to the agent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ShellInput {
    Data(Vec<u8>),
    Resize { cols: u32, rows: u32 },
    Close(ShellCloseReason),
}


/// A validated frame from the agent after `Open`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentFrame {
    Data(Vec<u8>),
    Keepalive,
    Close(AgentCloseReason),
}


/// One merged item of a running shell stream.
#[derive(Debug)]
pub enum ShellIn {
    Frame(ShellFrame),
    Silent,
    Transport(Status),
    Eof,
    Input(ShellInput),
}


/// An approved session waiting for its agent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingShell {
    pub start_deadline: u64,
    pub max_seconds: u64,
}


/// Pending sessions by identity and session id, and the number of sessions running.
#[derive(Debug, Default)]
pub struct GateTable {
    pub pending: HashMap<(Identity, String), PendingShell>,
    pub active: usize,
}


/// The sessions the platform approved; entries are added before the command is offered and taken once by the agent.
pub struct ShellGate {
    pub table: Mutex<GateTable>,
    pub clock: Box<ClockFn>,
}


/// One running session of the gate; dropping it gives the place back.
pub struct ActiveShell {
    pub gate: Arc<ShellGate>,
}


/// What `gate_take` returns: the lifetime of the session and its place.
pub struct ShellTake {
    pub max_seconds: u64,
    pub active: ActiveShell,
}


#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum GateError {
    #[error("shell gate is full")]
    Full,
    #[error("shell session id is not valid")]
    InvalidSessionId,
    #[error("shell session is already pending")]
    Duplicate,
}


/// The gate and the injected ends of the shell stream.
pub struct ShellState {
    pub gate: Arc<ShellGate>,
    pub sink: ShellSink,
    pub source: ShellSource,
}


/// What the budgets of one session have counted.
#[derive(Clone, Copy, Debug)]
pub struct ShellMeter {
    pub frames: u64,
    pub bytes: u64,
    pub window_started: Instant,
    pub window_frames: u32,
}


/// Everything a running shell stream needs.
pub struct ShellRun {
    pub state: Arc<ServerState>,
    pub shell: Arc<ShellState>,
    pub identity: Identity,
    pub session_id: String,
    pub started: Instant,
    pub lifetime: Duration,
    pub sender: mpsc::Sender<Result<ShellFrame, Status>>,
}
