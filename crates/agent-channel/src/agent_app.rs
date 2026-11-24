use crate::app::{debounce, keep_signals, reload_context, shared_log_audit};
use crate::client::{backoff_delay, connect_channel, deliver_events, heartbeat, random_jitter, run_commands_until};
use crate::error::{AppError, ChannelError};
use crate::model::{ClientTlsPaths, CommandRun, Delivered, ExecuteRefusal};
use crate::proto::EventBatch;
use crate::relay::{
    endpoint_addresses, hold_internal, is_rate_refusal, pinned_dialer, select_endpoint, stop_at, tripped, EndpointKind, HoldDown, Selected,
};
use crate::spool::{claim_spool, finish_spool, quarantine, suffixed, Spool, MAX_REJECTED_BYTES, REJECTED_SUFFIX};
use crate::spool_dirs::SpoolDirs;
use crate::tls::client_config;
use crate::types::{DialFn, ExecuteFn, PauseFn, SharedClientConfig, StopFuture};
use agent_command::cli::seconds_since_epoch;
use agent_command::keys::open_keys_engine;
use agent_command::model::{Action, Command, Verifier};
use agent_command::verify::open_verifier;
use core_audit::log::{open_file_log, owner_only};
use core_config::load::load_file;
use core_config::watch::watch_files;
use futures_util::StreamExt;
use serde::Deserialize;
use std::fs::OpenOptions;
use std::future::Future;
use std::io::Write;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_stream::wrappers::ReceiverStream;


pub const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");


pub const AGENT_MODULE: &str = "channel_agent";


/// Failed session attempts, dial and heartbeat and command stream together, before the agent gives up.
pub const MAX_AGENT_ATTEMPTS: u32 = 5;


/// Accepted commands waiting for the worker; a full queue refuses the command, reported to the server.
pub const WORKER_QUEUE: usize = 64;


#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentFile {
    pub server: String,
    pub server_name: String,
    #[serde(default)]
    pub relays: Vec<String>,
    pub certificate: PathBuf,
    pub key: PathBuf,
    pub platform_ca: PathBuf,
    pub tenant: String,
    pub agent_id: String,
    pub keys_file: PathBuf,
    pub state_file: PathBuf,
    pub audit_file: PathBuf,
    pub spool_file: PathBuf,
    pub sequence_file: PathBuf,
    pub executed_file: PathBuf,
}


/// What one agent run did: acknowledged event sequences, the command run, and the number of commands its worker recorded.
#[derive(Debug)]
pub struct AgentOutcome {
    pub acknowledged: Vec<u64>,
    pub event_failures: u32,
    pub internal_runs: u32,
    pub relay_runs: u32,
    pub run: CommandRun,
    pub executed: u64,
}


/// What event delivery settled in one run: the acknowledged sequences and how many deliveries failed.
#[derive(Debug)]
pub struct EventsOutcome {
    pub acknowledged: Vec<u64>,
    pub failures: u32,
}


/// The worker that records commands: the queue end handed to `ExecuteFn` and the task.
pub struct Worker {
    pub sender: mpsc::Sender<Command>,
    pub handle: JoinHandle<u64>,
}


pub fn load_agent_file(path: &Path) -> Result<AgentFile, AppError> {
    let file = load_file::<AgentFile>(path)?;
    endpoint_addresses(&file)?;
    Ok(file)
}


pub fn now_seconds() -> u64 {
    seconds_since_epoch(SystemTime::now().duration_since(UNIX_EPOCH))
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


/// Hands the command to the recording worker and returns at once; a full or closed queue is `Busy`, so the command is reported refused.
pub fn record_command(sender: &mpsc::Sender<Command>, command: Command) -> Result<(), ExecuteRefusal> {
    sender
        .try_send(command)
        .inspect_err(|error| tracing::warn!(%error, "worker queue refused a command"))
        .map_err(|_refused| ExecuteRefusal::Busy)
}


pub fn execute_fn(sender: mpsc::Sender<Command>) -> Box<ExecuteFn<'static>> {
    Box::new(move |command| record_command(&sender, command))
}


/// Routes `OpenShell` to the shell executor alone (its verdict decides, the record is best effort afterwards); every other action is recorded.
pub fn dispatch_command(sender: &mpsc::Sender<Command>, shell: Option<&ExecuteFn<'_>>, command: Command) -> Result<(), ExecuteRefusal> {
    match (&command.action, shell) {
        (Action::OpenShell { .. }, Some(executor)) => {
            let copy = command.clone();
            executor(command).inspect(|()| {
                if sender.try_send(copy).is_err() {
                    tracing::warn!("open-shell admitted, not recorded");
                }
            })
        }
        (Action::OpenShell { .. }, None) => {
            tracing::warn!("shell command refused: no shell executor");
            Err(ExecuteRefusal::NoShellExecutor)
        }
        (
            Action::Ping
            | Action::CollectStatus
            | Action::Isolate
            | Action::Kill { .. }
            | Action::RunScript { .. }
            | Action::Update { .. }
            | Action::Uninstall
            | Action::ChangePolicy { .. }
            | Action::InstallUpdates { .. }
            | Action::Reboot { .. },
            _,
        ) => record_command(sender, command),
    }
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


pub async fn session_attempt(dial: &DialFn, verifier: &Verifier, execute: &ExecuteFn<'_>) -> Result<CommandRun, crate::error::ChannelError> {
    session_attempt_until(dial, verifier, execute, Box::pin(std::future::pending())).await
}


/// One command session that ends cleanly when `stop` completes.
pub async fn session_attempt_until(
    dial: &DialFn,
    verifier: &Verifier,
    execute: &ExecuteFn<'_>,
    stop: StopFuture,
) -> Result<CommandRun, crate::error::ChannelError> {
    let channel = dial().await?;
    heartbeat(channel.clone(), AGENT_VERSION).await?;
    run_commands_until(channel, verifier, &now_seconds, execute, stop).await
}


/// Runs event delivery and the command stream side by side: neither waits for the other, each keeps its own deadlines and backoff.
pub async fn run_streams(
    events_dial: &DialFn,
    commands_dial: &DialFn,
    pause: &PauseFn,
    batches: Vec<EventBatch>,
    verifier: &Verifier,
    execute: &ExecuteFn<'_>,
    cut: Option<Instant>,
) -> (Result<Delivered, ChannelError>, Result<CommandRun, AppError>) {
    tokio::join!(
        deliver_events(events_dial, pause, batches),
        run_attempts(|| session_attempt_until(commands_dial, verifier, execute, Box::pin(stop_at(cut))), pause)
    )
}


/// What a run whose pinned endpoint failed settles with: both streams are cut at once, the claimed spool is kept for the next run.
pub fn lost_streams() -> (Result<Delivered, ChannelError>, Result<CommandRun, AppError>) {
    (Err(ChannelError::EndpointLost), Err(AppError::Channel(ChannelError::EndpointLost)))
}


/// A run that ended because the server refused on rate: the server answered, so nothing is held down.
pub fn ended_on_rate(run: &Result<CommandRun, AppError>) -> bool {
    matches!(run, Err(AppError::AttemptsExhausted { last: Some(last), .. }) if is_rate_refusal(last))
}


/// An internal run that failed holds the internal endpoint down; a relay run that failed, a rate refusal, or any run that ended well, does not.
pub fn note_run(hold: &HoldDown, selected: &Selected, run: &Result<CommandRun, AppError>) {
    if selected.kind == EndpointKind::Internal && run.is_err() && !ended_on_rate(run) {
        hold_internal(hold);
    }
}


/// A failed delivery is logged and counted, its batches stay in the claimed spool for the next run; a delivery that settled is written out.
pub fn settle_events(file: &AgentFile, spool: &Spool, delivery: Result<Delivered, ChannelError>) -> Result<EventsOutcome, AppError> {
    match delivery {
        Ok(delivered) => {
            quarantine(&suffixed(&file.spool_file, REJECTED_SUFFIX), &delivered.rejected, MAX_REJECTED_BYTES)?;
            let settled: Vec<u64> = delivered
                .acknowledged
                .iter()
                .copied()
                .chain(delivered.rejected.iter().map(|batch| batch.sequence))
                .collect();
            finish_spool(spool, &settled)?;
            Ok(EventsOutcome {
                acknowledged: delivered.acknowledged,
                failures: 0,
            })
        }
        Err(error) => {
            tracing::error!(%error, "event delivery failed, the spool is kept for the next run");
            Ok(EventsOutcome {
                acknowledged: Vec::new(),
                failures: 1,
            })
        }
    }
}


/// Settles the events, then always waits for the worker so no accepted command is lost to a failed settle; the settle error wins.
pub async fn settle_and_join(
    file: &AgentFile,
    spool: &Spool,
    delivery: Result<Delivered, ChannelError>,
    handle: JoinHandle<u64>,
) -> Result<(EventsOutcome, u64), AppError> {
    let settled = tokio::task::spawn_blocking({
        let owned_file = file.clone();
        let owned_spool = spool.clone();
        move || settle_events(&owned_file, &owned_spool, delivery)
    })
    .await;
    let joined = handle.await;
    let events = settled??;
    let executed = joined?;
    Ok((events, executed))
}


/// Heartbeats and runs the command stream while the spooled events are delivered; a failed event delivery never stops commands.
pub async fn run_agent(
    file: &AgentFile,
    _checked: &SpoolDirs,
    pause: &PauseFn,
    shell: Option<&ExecuteFn<'_>>,
    hold: &HoldDown,
) -> Result<AgentOutcome, AppError> {
    let addresses = endpoint_addresses(file)?;
    let config = client_config(&ClientTlsPaths {
        certificate: file.certificate.clone(),
        key: file.key.clone(),
        platform_ca: file.platform_ca.clone(),
    })?;
    let selected = run_attempts(|| select_endpoint(&addresses, &config, &file.server_name, hold), pause).await?;
    let (trip_sender, trip_receiver) = watch::channel(false);
    let trip = Arc::new(trip_sender);
    let dial = pinned_dialer(selected.address, config, file.server_name.clone(), Arc::clone(&trip));
    let spool = tokio::task::spawn_blocking({
        let owned = file.clone();
        move || claim_spool(&owned)
    })
    .await??;
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
    let sender = worker.sender;
    let execute = |command: Command| dispatch_command(&sender, shell, command);
    let streams = run_streams(
        dial.as_ref(),
        dial.as_ref(),
        pause,
        spool.batches.clone(),
        &verifier,
        &execute,
        selected.cut,
    );
    let (delivery, run) = tokio::select! {
        outcome = streams => outcome,
        () = tripped(trip_receiver) => lost_streams(),
    };
    drop(sender);
    note_run(hold, &selected, &run);
    let (events, executed) = settle_and_join(file, &spool, delivery, worker.handle).await?;
    Ok(AgentOutcome {
        acknowledged: events.acknowledged,
        event_failures: events.failures,
        internal_runs: u32::from(selected.kind == EndpointKind::Internal),
        relay_runs: u32::from(selected.kind == EndpointKind::Relay),
        run: run?,
        executed,
    })
}
