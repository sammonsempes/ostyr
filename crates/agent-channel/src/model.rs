use crate::types::{CommandSource, EventSink};
use secrecy::SecretString;
use serde::Deserialize;
use std::collections::{BTreeSet, HashMap};
use std::path::PathBuf;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex};
use std::time::Instant;


pub const IDENTITY_URI_PREFIX: &str = "urn:ostyr:agent:";


pub const MAX_IDENTITY_COMPONENT_LENGTH: usize = 64;


pub const CONNECT_TIMEOUT_SECONDS: u64 = 10;


pub const ALPN_H2: &[u8] = b"h2";


pub const HEARTBEAT_PATH: &str = "/ostyr.agent.v1.Heartbeat/Beat";


pub const EVENTS_PATH: &str = "/ostyr.agent.v1.Events/Push";


pub const SUBSCRIBE_PATH: &str = "/ostyr.agent.v1.Commands/Subscribe";


pub const REPORT_PATH: &str = "/ostyr.agent.v1.Commands/Report";


pub const DEFAULT_HEARTBEAT_INTERVAL_SECONDS: u64 = 30;


pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 1_048_576;


pub const DEFAULT_MAX_STREAMS_PER_AGENT: usize = 4;


pub const DEFAULT_MAX_REQUESTS_PER_WINDOW: u32 = 200;


pub const DEFAULT_RATE_WINDOW_SECONDS: u64 = 1;


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
}


impl Default for ChannelSettings {
    fn default() -> Self {
        Self {
            heartbeat_interval_seconds: DEFAULT_HEARTBEAT_INTERVAL_SECONDS,
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
            max_streams_per_agent: DEFAULT_MAX_STREAMS_PER_AGENT,
            max_requests_per_window: DEFAULT_MAX_REQUESTS_PER_WINDOW,
            rate_window_seconds: DEFAULT_RATE_WINDOW_SECONDS,
        }
    }
}


/// Refusals and outcomes since the server started.
#[derive(Debug, Default)]
pub struct Counters {
    pub oversized: AtomicU64,
    pub rate_limited: AtomicU64,
    pub stream_limited: AtomicU64,
    pub identity_mismatch: AtomicU64,
    pub events_acknowledged: AtomicU64,
    pub commands_accepted: AtomicU64,
    pub commands_refused: AtomicU64,
}


/// What one agent currently holds: open streams and the requests of the current rate window.
#[derive(Clone, Debug)]
pub struct AgentLoad {
    pub streams: usize,
    pub window_started: Instant,
    pub window_count: u32,
}


/// Shared by every connection: bounds, counters, per-agent load and the two injected ends (event sink, command source).
pub struct ServerState {
    pub settings: ChannelSettings,
    pub counters: Counters,
    pub load: Mutex<HashMap<Identity, AgentLoad>>,
    pub events: EventSink,
    pub commands: CommandSource,
}


/// One open stream of an agent; dropping it gives the slot back.
pub struct StreamPermit {
    pub state: Arc<ServerState>,
    pub identity: Identity,
}


/// Everything a running `Events` stream needs; the permit goes with the stream.
pub struct PushSession {
    pub state: Arc<ServerState>,
    pub identity: Identity,
    pub permit: StreamPermit,
}


/// What the agent decided about one command envelope.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandVerdict {
    pub digest: Vec<u8>,
    pub accepted: bool,
    pub reason: String,
}
