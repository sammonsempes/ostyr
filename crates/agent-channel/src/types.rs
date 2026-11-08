use crate::error::ChannelError;
use crate::model::{Identity, Revocations, ServerState};
use crate::proto::{CommandEnvelope, EventAck, EventBatch};
use core_config::types::SharedAuditFn;
use std::error::Error;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio::sync::watch;
use tokio_stream::Stream;
use tonic::transport::Channel;
use tonic::Status;


pub type SharedServerConfig = Arc<rustls::ServerConfig>;


pub type SharedClientConfig = Arc<rustls::ClientConfig>;


pub type IncomingConnections = Pin<Box<dyn Stream<Item = io::Result<TcpStream>> + Send>>;


pub type ShutdownSignal = Pin<Box<dyn Future<Output = ()> + Send>>;


pub type RevocationWatch = watch::Receiver<Revocations>;


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


pub type SharedState = Arc<ServerState>;


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
