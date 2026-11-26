use crate::error::IsolationError;
use crate::isolation::{isolate, status_audited, IsolationEnv};
use crate::model::{Endpoint, IsolationSettings, LinuxFile, StateDir};
use crate::settings::invalid_isolation_settings;
use crate::types::NftFn;
use agent_channel::model::ExecuteRefusal;
use agent_channel::types::ExecuteFn;
use agent_command::model::{Action, Command};
use core_audit::model::{Actor, ActorKind, NewEntry, Outcome};
use core_config::parse::{parse_document, read_file};
use core_config::types::SharedAuditFn;
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::future::Future;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use time::OffsetDateTime;
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio::sync::Notify;
use tokio_stream::wrappers::ReceiverStream;


/// Orders waiting for the worker; a full queue refuses the command as busy.
pub const ADMIN_QUEUE: usize = 8;


pub const COMMAND_MODULE: &str = "agent_linux_command";


pub const AGENT_LINUX_VERSION: &str = env!("CARGO_PKG_VERSION");


pub const REASON_SETTINGS_UNREADABLE: &str = "settings_unreadable";


pub const REASON_SETTINGS_INVALID: &str = "settings_invalid";


pub const REASON_ENDPOINT_NOT_LISTED: &str = "channel_endpoint_not_listed";


pub const REASON_MISMATCH: &str = "table_mismatch";


pub const REASON_TIMEOUT: &str = "nft_timeout";


pub const REASON_FAILED: &str = "failed";


/// The three actions the Linux agent runs itself besides the shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminKind {
    Ping,
    CollectStatus,
    Isolate,
}


/// One verified command handed to the worker: its kind and its sequence only, never the command itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdminOrder {
    pub kind: AdminKind,
    pub sequence: u64,
}


/// What the worker needs: the injected `nft` runner, the held state directory, the audit, the settings file read for each order and the addresses the channel really uses.
pub struct AdminEnv<'a> {
    pub run: NftFn,
    pub nft: &'a Path,
    pub state: &'a StateDir,
    pub tenant: &'a str,
    pub audit: &'a SharedAuditFn,
    pub settings_file: &'a Path,
    pub channel: &'a [SocketAddr],
    pub restart: &'a Notify,
}


pub fn kind_name(kind: AdminKind) -> &'static str {
    match kind {
        AdminKind::Ping => "ping",
        AdminKind::CollectStatus => "collect_status",
        AdminKind::Isolate => "isolate",
    }
}


/// The order of a command, none for any other action.
pub fn order_of(command: &Command) -> Option<AdminOrder> {
    let kind = match command.action {
        Action::Ping => Some(AdminKind::Ping),
        Action::CollectStatus => Some(AdminKind::CollectStatus),
        Action::Isolate => Some(AdminKind::Isolate),
        _ => None,
    };
    kind.map(|accepted| AdminOrder {
        kind: accepted,
        sequence: command.sequence,
    })
}


pub fn admin_queue() -> (Sender<AdminOrder>, Receiver<AdminOrder>) {
    channel(ADMIN_QUEUE)
}


/// The executor of the three actions: it only queues and returns at once; a full or closed queue is `Busy`, any other action `Invalid`.
pub fn admin_execute_fn(queue: Sender<AdminOrder>) -> Box<ExecuteFn<'static>> {
    Box::new(move |command| match order_of(&command) {
        Some(order) => queue.try_send(order).map_err(|refused| {
            let kind = kind_name(order.kind);
            let sequence = order.sequence;
            let closed = matches!(refused, TrySendError::Closed(_));
            tracing::warn!(kind, sequence, closed, "admin command refused, command lost");
            ExecuteRefusal::Busy
        }),
        None => Err(ExecuteRefusal::Invalid),
    })
}


/// The socket address of an isolation endpoint exactly as the ruleset renders it (settings validation refuses a mapped address, so nothing is folded).
pub fn endpoint_socket(endpoint: &Endpoint) -> SocketAddr {
    SocketAddr::new(endpoint.address, endpoint.port)
}


/// True when every address the channel uses is a listed TCP flow: an isolation must never cut the agent's own channel.
pub fn channel_listed(settings: &IsolationSettings, channel: &[SocketAddr]) -> bool {
    channel
        .iter()
        .all(|address| settings.endpoints.iter().any(|endpoint| endpoint_socket(endpoint) == *address))
}


/// Reads the settings file once: the parsed value, the SHA-256 of the exact text parsed and the validation, all from that one read.
pub fn read_settings(path: &Path) -> Result<(LinuxFile, String), IsolationError> {
    let text = read_file(path)?;
    let file = parse_document::<LinuxFile>(&text, &path.display().to_string())?;
    let invalid = invalid_isolation_settings(&file);
    if invalid.is_empty() {
        Ok((file, format!("{:x}", Sha256::digest(text.as_bytes()))))
    } else {
        Err(IsolationError::Settings(invalid.join(", ")))
    }
}


pub fn isolation_env<'a>(env: &AdminEnv<'a>) -> IsolationEnv<'a> {
    IsolationEnv {
        run: env.run,
        nft: env.nft,
        state: env.state,
        tenant: env.tenant,
        audit: env.audit,
    }
}


/// Runs one order; the success text is the status line of the audit.
pub async fn run_order(env: &AdminEnv<'_>, order: AdminOrder) -> Result<String, IsolationError> {
    match order.kind {
        AdminKind::Ping => Ok("pong".to_owned()),
        AdminKind::CollectStatus => {
            let (file, digest) = read_settings(env.settings_file)?;
            let status = status_audited(&isolation_env(env), &file.isolation).await?;
            Ok(format!("isolation={status:?} version={AGENT_LINUX_VERSION} settings_sha256={digest}"))
        }
        AdminKind::Isolate => {
            let (file, digest) = read_settings(env.settings_file)?;
            if channel_listed(&file.isolation, env.channel) {
                isolate(&isolation_env(env), &file.isolation).await?;
                Ok(format!("isolated settings_sha256={digest}"))
            } else {
                Err(IsolationError::ChannelNotListed)
            }
        }
    }
}


/// The fixed reason of a failure, never the error text.
pub fn reason_of(error: &IsolationError) -> &'static str {
    match error {
        IsolationError::Config(_) => REASON_SETTINGS_UNREADABLE,
        IsolationError::Settings(_) | IsolationError::NoEndpoints => REASON_SETTINGS_INVALID,
        IsolationError::ChannelNotListed => REASON_ENDPOINT_NOT_LISTED,
        IsolationError::Mismatch(_) => REASON_MISMATCH,
        IsolationError::Timeout => REASON_TIMEOUT,
        _ => REASON_FAILED,
    }
}


pub fn command_entry(tenant: &str, order: AdminOrder, outcome: &Result<String, IsolationError>) -> NewEntry {
    let kind = kind_name(order.kind);
    let (result, reason, status) = match outcome {
        Ok(text) => ("ok", None, Some(text.clone())),
        Err(error) => ("failed", Some(reason_of(error)), None),
    };
    NewEntry {
        timestamp: OffsetDateTime::now_utc(),
        actor: Actor {
            kind: ActorKind::System,
            id: COMMAND_MODULE.to_owned(),
        },
        tenant: tenant.to_owned(),
        module: COMMAND_MODULE.to_owned(),
        action: format!("command.{kind}"),
        target: format!("sequence {}", order.sequence),
        outcome: if reason.is_none() { Outcome::Success } else { Outcome::Failure },
        request_id: format!("command-{kind}-{}", order.sequence),
        justification: status,
        parameters: std::iter::once(("result", result))
            .chain(reason.map(|fixed| ("reason", fixed)))
            .map(|(key, value)| (key.to_owned(), value.to_owned()))
            .collect(),
    }
}


/// Runs the order, audits kind, sequence and result, and asks the channel to redial after a successful isolation.
pub async fn settle_order(env: &AdminEnv<'_>, order: AdminOrder) {
    let outcome = run_order(env, order).await;
    let kind = kind_name(order.kind);
    let sequence = order.sequence;
    let result = if outcome.is_ok() { "ok" } else { "failed" };
    tracing::info!(kind, sequence, result, "admin command settled");
    (env.audit)(command_entry(env.tenant, order, &outcome))
        .inspect_err(|error| tracing::error!(%error, "command audit failed"))
        .ok();
    if order.kind == AdminKind::Isolate && outcome.is_ok() {
        env.restart.notify_one();
    }
}


/// One worker, orders one at a time; once `stopping` is set queued orders are logged lost, the one in flight is settled. Returns the settled count.
pub async fn run_admin_worker(orders: Receiver<AdminOrder>, env: &AdminEnv<'_>, stopping: &AtomicBool) -> u64 {
    ReceiverStream::new(orders)
        .fold(0, |count, order| async move {
            if stopping.load(Ordering::SeqCst) {
                let kind = kind_name(order.kind);
                let sequence = order.sequence;
                tracing::warn!(kind, sequence, "admin command not started at stop, command lost");
                count
            } else {
                settle_order(env, order).await;
                count + 1
            }
        })
        .await
}


/// Runs the producers until they end or `terminate` fires, with the admin worker beside them (never inside the race): on terminate or a producer error it sets `stopping`, and the order in flight is awaited and audited before this returns.
pub async fn run_with_admin<Done, Failure>(
    producers: impl Future<Output = Result<Done, Failure>>,
    admin: impl Future<Output = u64>,
    terminate: impl Future<Output = ()>,
    stopping: &AtomicBool,
) -> Option<Result<Done, Failure>> {
    let guarded = async {
        let ended = tokio::select! {
            joined = producers => Some(joined),
            () = terminate => None,
        };
        let stop_admin = !matches!(ended, Some(Ok(_)));
        stopping.store(stop_admin, Ordering::SeqCst);
        ended
    };
    tokio::join!(guarded, admin).0
}
