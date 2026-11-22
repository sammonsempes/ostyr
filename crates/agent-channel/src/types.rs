use crate::error::ChannelError;
use crate::model::{ChannelSettings, Identity, Revocations, ServerState, ShellInput, ShellSinkEvent, ShellState};
use crate::proto::{CommandEnvelope, EventAck, EventBatch, ShellFrame};
use agent_command::model::Command;
use arc_swap::ArcSwap;
use core_config::types::SharedAuditFn;
use std::collections::VecDeque;
use std::error::Error;
use std::fs::File;
use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_stream::Stream;
use tonic::transport::Channel;
use tonic::Status;


pub type EventWriter = Box<dyn Write + Send>;


pub type SyncFn = Box<dyn Fn() -> io::Result<()> + Send>;


pub type SharedServerConfig = Arc<rustls::ServerConfig>;


pub type SharedClientConfig = Arc<rustls::ClientConfig>;


pub type IncomingConnections = Pin<Box<dyn Stream<Item = io::Result<TcpStream>> + Send>>;


pub type ShutdownSignal = Pin<Box<dyn Future<Output = ()> + Send>>;


pub type RevocationWatch = watch::Receiver<Revocations>;


pub type SharedSettings = Arc<ArcSwap<ChannelSettings>>;


pub type RevocationSender = Arc<watch::Sender<Revocations>>;


pub type BoxError = Box<dyn Error + Send + Sync>;


pub type SinkFuture = Pin<Box<dyn Future<Output = Result<(), BoxError>> + Send>>;


/// Durably accepts one batch of an agent; the batch is acknowledged only when this succeeds.
pub type EventSink = Box<dyn Fn(Identity, EventBatch) -> SinkFuture + Send + Sync>;


pub type CommandStream = Pin<Box<dyn Stream<Item = Vec<u8>> + Send>>;


/// Opens the stream of `agent-command` envelope bytes destined to one agent.
pub type CommandSource = Box<dyn Fn(Identity) -> CommandStream + Send + Sync>;


pub type AckStream = Pin<Box<dyn Stream<Item = Result<EventAck, Status>> + Send>>;


pub type EnvelopeStream = Pin<Box<dyn Stream<Item = Result<CommandEnvelope, Status>> + Send>>;


/// Receives what an agent shell sends; each call is awaited under a deadline.
pub type ShellSink = Box<dyn Fn(Identity, String, ShellSinkEvent) -> SinkFuture + Send + Sync>;


pub type ShellInputStream = Pin<Box<dyn Stream<Item = ShellInput> + Send>>;


/// Opens what the platform sends to the shell of one session.
pub type ShellSource = Box<dyn Fn(Identity, String) -> ShellInputStream + Send + Sync>;


pub type ShellInbound = Pin<Box<dyn Stream<Item = Result<(ShellFrame, usize), Status>> + Send>>;


/// The first inbound item of a shell stream, or the open deadline.
pub type FirstShellItem = Result<Option<Result<(ShellFrame, usize), Status>>, tokio::time::error::Elapsed>;


/// The wire lengths of the shell messages the scanner has seen and the handler has not yet paired with a decoded frame.
pub type WireLengths = Arc<Mutex<VecDeque<usize>>>;


pub type ShellStream = Pin<Box<dyn Stream<Item = Result<ShellFrame, Status>> + Send>>;


pub type SharedShell = Arc<ShellState>;


pub type SharedState = Arc<ServerState>;


/// Receives each accepted command as it arrives; it must hand the work off and return quickly, true when the work was taken over.
pub type ExecuteFn = dyn Fn(Command) -> bool + Send + Sync;


/// Reads the monotonic time for the server limiter; production passes `system_now`.
pub type NowFn = dyn Fn() -> Instant + Send + Sync;


pub type ClockFn = dyn Fn() -> u64 + Send + Sync;


pub type GrpcResponse = http::Response<tonic::body::Body>;


/// Writes one audit record; the server example injects the append of the platform audit log.
pub type AuditSink = Box<SharedAuditFn>;


pub type DialFuture = Pin<Box<dyn Future<Output = Result<Channel, ChannelError>> + Send>>;


/// Opens a fresh channel to the server; called again after every failure.
pub type DialFn = dyn Fn() -> DialFuture + Send + Sync;


pub type PauseFuture = Pin<Box<dyn Future<Output = ()> + Send>>;


/// Waits for the given delay; injected so tests do not sleep.
pub type PauseFn = dyn Fn(Duration) -> PauseFuture + Send + Sync;


/// Reads the first lines of a locked claimed file and whether the overflow went back to the spool; injected so tests can fail it.
pub type LoadFn = fn(&File, &Path, u64, usize) -> io::Result<(Vec<String>, bool)>;


/// The function that opens the old quarantine and the lock attempts of one rewrite.
pub type RewriteHooks = (fn(&Path) -> io::Result<Option<File>>, u32);


pub type AclJudge = fn(&File, &Path) -> Result<(), sys_windows::types::DirAclError>;


/// Judges the fixed-name entries of the spool directories that already exist; injected so tests can refuse or record them.
pub type EntriesJudge = fn(&[PathBuf]) -> Result<(), sys_windows::types::DirAclError>;
