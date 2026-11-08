use crate::app::{debounce, keep_signals, reload_context, shared_log_audit};
use crate::client::{backoff_delay, connect_channel, deliver_events, heartbeat, random_jitter, run_commands};
use crate::error::AppError;
use crate::model::{ClientTlsPaths, CommandRun};
use crate::proto::EventBatch;
use crate::tls::client_config;
use crate::types::{DialFn, ExecuteFn, PauseFn, SharedClientConfig};
use agent_command::cli::seconds_since_epoch;
use agent_command::keys::open_keys_engine;
use agent_command::model::{Command, Verifier};
use agent_command::verify::open_verifier;
use core_audit::log::{open_file_log, owner_only};
use core_config::load::load_file;
use core_config::watch::watch_files;
use futures_util::StreamExt;
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::future::Future;
use std::io::{self, BufRead, BufReader, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_stream::wrappers::ReceiverStream;


pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");


pub const AGENT_MODULE: &str = "channel_agent";


/// Failed session attempts, dial and heartbeat and command stream together, before the agent gives up.
pub const MAX_AGENT_ATTEMPTS: u32 = 5;


/// Event lines read from the spool file per run.
pub const MAX_SPOOL_BATCHES: usize = 1_000;


/// Accepted commands waiting for the worker; a full queue drops the command and logs it.
pub const WORKER_QUEUE: usize = 64;


#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFile {
    pub server: String,
    pub server_name: String,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub platform_ca: PathBuf,
    pub tenant: String,
    pub agent_id: String,
    pub keys_file: PathBuf,
    pub state_file: PathBuf,
    pub audit_file: PathBuf,
    pub spool_file: PathBuf,
    pub executed_file: PathBuf,
}


/// What one agent run did: acknowledged event sequences, the command run, and the number of commands its worker recorded.
#[derive(Debug)]
pub struct AgentOutcome {
    pub acknowledged: Vec<u64>,
    pub run: CommandRun,
    pub executed: u64,
}


/// The worker that records commands: the queue end handed to `ExecuteFn` and the task.
pub struct Worker {
    pub sender: mpsc::Sender<Command>,
    pub handle: JoinHandle<u64>,
}


pub fn load_agent_file(path: &Path) -> Result<AgentFile, AppError> {
    Ok(load_file::<AgentFile>(path)?)
}


pub fn now_seconds() -> u64 {
    seconds_since_epoch(SystemTime::now().duration_since(UNIX_EPOCH))
}


/// One event batch per line, sequence numbers from 1.
pub fn batches_of(lines: impl Iterator<Item = io::Result<String>>, file: &AgentFile) -> io::Result<Vec<EventBatch>> {
    (1..)
        .zip(lines)
        .map(|(sequence, line)| {
            line.map(|text| EventBatch {
                sequence,
                ecs_json: text.into_bytes(),
                tenant: file.tenant.clone(),
                agent_id: file.agent_id.clone(),
            })
        })
        .collect()
}


/// The spool file as event batches, at most `MAX_SPOOL_BATCHES`.
pub fn read_spool(path: &Path, file: &AgentFile) -> Result<Vec<EventBatch>, AppError> {
    let lines = BufReader::new(File::open(path)?).lines().take(MAX_SPOOL_BATCHES);
    batches_of(lines, file).map_err(AppError::from)
}


/// Appends one line per command; a failed write is logged.
pub async fn record_commands<Output: Write>(receiver: mpsc::Receiver<Command>, mut out: Output) -> u64 {
    ReceiverStream::new(receiver)
        .fold(0, |count, command| {
            let written =
                writeln!(out, "{} {} {} {:?}", command.tenant, command.agent_id, command.sequence, command.action).and_then(|()| out.flush());
            match written {
                Ok(()) => std::future::ready(count + 1),
                Err(error) => {
                    tracing::error!(%error, "command not recorded");
                    std::future::ready(count)
                }
            }
        })
        .await
}


pub fn start_worker(path: &Path) -> Result<Worker, AppError> {
    let out = owner_only(OpenOptions::new().append(true).create(true)).open(path)?;
    let (sender, receiver) = mpsc::channel(WORKER_QUEUE);
    Ok(Worker {
        sender,
        handle: tokio::spawn(record_commands(receiver, out)),
    })
}


/// Hands each accepted command to the worker and returns at once; a full queue is logged.
pub fn execute_fn(sender: mpsc::Sender<Command>) -> Box<ExecuteFn> {
    Box::new(move |command| {
        if let Err(error) = sender.try_send(command) {
            tracing::warn!(%error, "worker queue refused a command");
        }
    })
}


pub fn dialer(address: SocketAddr, config: SharedClientConfig, server_name: String) -> Box<DialFn> {
    Box::new(move || {
        let shared = Arc::clone(&config);
        let name = server_name.clone();
        Box::pin(async move { connect_channel(address, shared, &name).await })
    })
}


/// Any error of an attempt, `CallTimedOut` included, is a failed attempt: logged, a jittered backoff, then the next one.
pub async fn run_attempts<Output, Attempt, Pending>(attempt: Attempt, pause: &PauseFn) -> Result<Output, AppError>
where
    Attempt: Fn() -> Pending,
    Pending: Future<Output = Result<Output, crate::error::ChannelError>>,
{
    let mut failures = 0;
    let mut outcome = None;
    let mut last = None;
    while outcome.is_none() && failures < MAX_AGENT_ATTEMPTS {
        match attempt().await {
            Ok(output) => outcome = Some(output),
            Err(error) => {
                tracing::warn!(%error, failures, "agent session attempt failed");
                last = Some(error);
                pause(backoff_delay(failures, random_jitter())).await;
                failures += 1;
            }
        }
    }
    outcome.ok_or(AppError::AttemptsExhausted {
        attempts: failures,
        last: last.map(Box::new),
    })
}


pub async fn session_attempt(dial: &DialFn, verifier: &Verifier, execute: &ExecuteFn) -> Result<CommandRun, crate::error::ChannelError> {
    let channel = dial().await?;
    heartbeat(channel.clone(), AGENT_VERSION).await?;
    run_commands(channel, verifier, &now_seconds, execute).await
}


/// Sends the spooled events, then heartbeats and runs the command stream until the server ends it; accepted commands go to a worker.
pub async fn run_agent(file: &AgentFile, pause: &PauseFn) -> Result<AgentOutcome, AppError> {
    let address: SocketAddr = file.server.parse()?;
    let config = client_config(&ClientTlsPaths {
        certificate: file.certificate.clone(),
        key: file.key.clone(),
        platform_ca: file.platform_ca.clone(),
    })?;
    let dial = dialer(address, config, file.server_name.clone());
    let acknowledged = deliver_events(dial.as_ref(), pause, read_spool(&file.spool_file, file)?).await?;
    let log = Arc::new(open_file_log(&file.audit_file)?);
    let keys = Arc::new(open_keys_engine(
        file.keys_file.clone(),
        shared_log_audit(&log),
        reload_context(&file.keys_file, AGENT_MODULE, &file.tenant, "keys-reload"),
    )?);
    let _watch = watch_files(Arc::clone(&keys), std::slice::from_ref(&file.keys_file), debounce())?;
    let _signals = keep_signals(Arc::clone(&keys))?;
    let verifier = open_verifier(&file.agent_id, &file.tenant, keys, &file.state_file)?;
    let worker = start_worker(&file.executed_file)?;
    let execute = execute_fn(worker.sender);
    let dial_ref = dial.as_ref();
    let verifier_ref = &verifier;
    let execute_ref = execute.as_ref();
    let run = run_attempts(move || session_attempt(dial_ref, verifier_ref, execute_ref), pause).await?;
    drop(execute);
    let executed = worker.handle.await?;
    Ok(AgentOutcome { acknowledged, run, executed })
}
