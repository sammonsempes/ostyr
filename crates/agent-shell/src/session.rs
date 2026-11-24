use crate::banner::shell_banner;
use crate::error::ShellError;
use crate::model::{
    expires_at_of, idle_seconds_of, max_seconds_of, session_id_of, EndReason, PtyHandle, SessionHooks, ShellEnv, ShellOutcome, ShellShared,
    VerifiedOpenShell, SHELL_EXIT_FLUSH_SECONDS, SHELL_INPUT_BYTES, SHELL_QUEUE_CAPACITY,
};
use crate::queue::release_slot;
use crate::store::record_session;
use crate::types::{AttachFn, BuildFn, InputChunks, ShellSlot};
use crate::verified::check_start;
use agent_channel::error::ChannelError;
use agent_channel::model::ShellClientEnd;
use agent_channel::shell_client::attach_shell;
use agent_channel::types::{ShellReader, ShellWriter};
use bytes::Bytes;
use futures_util::{stream, StreamExt, TryStreamExt};
use std::future::{pending, ready};
use std::io;
use std::sync::PoisonError;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::{sleep_until, timeout, Instant};
use tokio_stream::wrappers::ReceiverStream;
use tokio_util::io::ReaderStream;
use tonic::transport::Channel;


/// The production `AttachFn`: the real `attach_shell` over the channel the session dialled.
pub fn attach_fn() -> Box<AttachFn> {
    Box::new(|channel, session_id, reader, writer| Box::pin(async move { attach_shell(channel, &session_id, reader, writer).await }))
}


/// A cleanup that left nothing behind is fine; a failure or a leftover process is not.
pub fn cleanup_verdict(cleanup: io::Result<usize>) -> Result<(), ShellError> {
    match cleanup {
        Ok(0) => Ok(()),
        Ok(left) => Err(ShellError::Leftover(left)),
        Err(source) => Err(ShellError::Cleanup(source)),
    }
}


/// The terminal input of the platform: a writer for the attach, and the chunks it wrote, through a bounded in-memory pipe that fails every write once it is closed.
pub fn input_pipe() -> (ShellWriter, InputChunks) {
    let (writer, reader) = tokio::io::duplex(SHELL_INPUT_BYTES);
    (Box::new(writer), Box::pin(ReaderStream::new(reader)))
}


pub async fn forward_input(input: &mpsc::Sender<Vec<u8>>, item: Result<io::Result<Bytes>, tokio_stream::Elapsed>) -> Result<(), EndReason> {
    let read = item.map_err(|_elapsed| EndReason::Idle)?;
    let bytes = read.map_err(|error| {
        tracing::warn!(%error, "shell input read failed");
        EndReason::ShellGone
    })?;
    input.send(bytes.to_vec()).await.map_err(|_closed| EndReason::ShellGone)
}


/// Writes the platform input to the shell. Only these writes refresh the idle timer, never the output; the end of the input is not an end of the session.
pub async fn pump_input(chunks: InputChunks, input: mpsc::Sender<Vec<u8>>, idle: Duration) -> EndReason {
    let ended = tokio_stream::StreamExt::timeout(chunks, idle)
        .map(Ok)
        .try_fold(input, |sender, item| async move { forward_input(&sender, item).await.map(|()| sender) })
        .await;
    match ended {
        Err(reason) => reason,
        Ok(_input) => pending().await,
    }
}


pub fn attach_end(attached: Result<ShellClientEnd, ChannelError>) -> EndReason {
    match attached {
        Ok(end) => EndReason::Attached(end),
        Err(error) => {
            tracing::warn!(%error, "shell attach failed");
            EndReason::AttachFailed
        }
    }
}


/// The shell exited: the attach gets `SHELL_EXIT_FLUSH_SECONDS` to deliver the last output, then the session ends as `ShellExited`.
pub async fn flush_after_exit(attach: &mut crate::types::AttachFuture) -> EndReason {
    match timeout(Duration::from_secs(SHELL_EXIT_FLUSH_SECONDS), attach).await {
        Ok(attached) => {
            let end = attach_end(attached);
            tracing::info!(?end, "shell attach ended after the exit");
        }
        Err(_elapsed) => tracing::warn!(seconds = SHELL_EXIT_FLUSH_SECONDS, "shell attach did not end after the exit"),
    }
    EndReason::ShellExited
}


/// Runs the shell until the first end; every limit runs on tokio time from the PTY start and is never extended.
pub async fn drive(order: &VerifiedOpenShell, channel: Channel, pty: PtyHandle, env: &ShellEnv<'_>) -> EndReason {
    let PtyHandle { output, input, mut exit } = pty;
    let max_deadline = Instant::now() + Duration::from_secs(u64::from(max_seconds_of(order)));
    let idle = Duration::from_secs(u64::from(idle_seconds_of(order)));
    let banner: io::Result<Vec<u8>> = Ok(shell_banner(order, &env.agent_id));
    let reader: ShellReader = Box::pin(stream::once(ready(banner)).chain(output));
    let (writer, chunks) = input_pipe();
    let mut attach = (env.attach)(channel, session_id_of(order).to_owned(), reader, writer);
    tokio::select! {
        biased;
        () = sleep_until(max_deadline) => EndReason::MaxSeconds,
        ended = pump_input(chunks, input, idle) => ended,
        attached = &mut attach => attach_end(attached),
        () = &mut exit => flush_after_exit(&mut attach).await,
    }
}


/// Why a session logs as it does.
pub fn log_outcome(outcome: &Result<ShellOutcome, ShellError>) {
    match outcome {
        Ok(ended) => tracing::info!(session = %ended.session_id, reason = ?ended.reason, clean = ended.cleanup_clean, "shell session ended"),
        Err(error) => {
            let cause = std::error::Error::source(error).map_or_else(String::new, ToString::to_string);
            tracing::warn!(%error, %cause, "shell session refused");
        }
    }
}


/// One session: expiry, cleanup of what is left, the one-use record (burned even if the attach fails), dial, spawn, drive, cleanup on every end.
pub async fn run_shell_session(order: VerifiedOpenShell, env: &ShellEnv<'_>) -> Result<ShellOutcome, ShellError> {
    let now = (env.clock)();
    check_start(&order, now)?;
    cleanup_verdict((env.cleanup)().await)?;
    {
        let _held = env.store_lock.lock().unwrap_or_else(PoisonError::into_inner);
        record_session(&env.store_directory, env.store_owner, session_id_of(&order), expires_at_of(&order), now)?;
    }
    let channel = (env.dial)().await.map_err(ShellError::Dial)?;
    let ended = match (env.spawn)(&order).await {
        Ok(pty) => Ok(drive(&order, channel, pty, env).await),
        Err(source) => Err(ShellError::Spawn(source)),
    };
    let cleanup_clean = cleanup_verdict((env.cleanup)().await)
        .inspect_err(|error| tracing::error!(%error, "shell cleanup after the session failed"))
        .is_ok();
    ended.map(|reason| ShellOutcome {
        session_id: session_id_of(&order).to_owned(),
        reason,
        cleanup_clean,
    })
}


/// Runs the queued sessions one after another; the slot is released after each one, so a new `OpenShell` is admitted only then.
pub async fn run_shell_worker(orders: mpsc::Receiver<VerifiedOpenShell>, slot: ShellSlot, env: &ShellEnv<'_>) -> u64 {
    ReceiverStream::new(orders)
        .then(|order| {
            let released = &slot;
            async move {
                let outcome = run_shell_session(order, env).await;
                log_outcome(&outcome);
                release_slot(released);
            }
        })
        .fold(0, |count, ()| ready(count + 1))
        .await
}


/// The environment of one session: what the process shares and the hooks built for that session.
pub fn session_env<'env>(shared: &'env ShellShared<'_>, hooks: &'env SessionHooks) -> ShellEnv<'env> {
    ShellEnv {
        agent_id: shared.agent_id.clone(),
        store_directory: shared.store_directory.clone(),
        store_owner: shared.store_owner,
        store_lock: &shared.store_lock,
        clock: shared.clock,
        dial: shared.dial,
        spawn: hooks.spawn.as_ref(),
        attach: shared.attach,
        cleanup: hooks.cleanup.as_ref(),
    }
}


/// The switch is read again when the session starts: an order queued before it was turned off is refused.
pub fn check_enabled(shared: &ShellShared<'_>) -> Result<(), ShellError> {
    if (shared.enabled)() {
        Ok(())
    } else {
        Err(ShellError::Disabled)
    }
}


/// When the account now resolves to another uid, the earlier uid is swept only if no passwd line holds it any more (a reassigned uid is an operator step); a leftover refuses the session.
pub async fn clear_previous(previous: Option<&SessionHooks>, hooks: &SessionHooks) -> Result<(), ShellError> {
    match previous {
        Some(earlier) if earlier.uid != hooks.uid && hooks.previous_holders > 0 => Err(ShellError::PreviousUidReassigned),
        Some(earlier) if earlier.uid != hooks.uid => cleanup_verdict((earlier.cleanup)().await),
        _ => Ok(()),
    }
}


/// The switch, the account resolution of this session and the cleanup of an earlier uid, in that order.
pub async fn prepare_session(
    shared: &ShellShared<'_>,
    account: &str,
    build: BuildFn,
    previous: Option<&SessionHooks>,
) -> Result<SessionHooks, ShellError> {
    check_enabled(shared)?;
    let hooks = build(account, previous.map(|earlier| earlier.uid))?;
    clear_previous(previous, &hooks).await?;
    Ok(hooks)
}


/// One session with its own hooks; the hooks come back as the next session's `previous`, a refusal keeps the old ones.
pub async fn run_prepared(
    order: VerifiedOpenShell,
    shared: &ShellShared<'_>,
    account: &str,
    build: BuildFn,
    previous: Option<SessionHooks>,
) -> (Result<ShellOutcome, ShellError>, Option<SessionHooks>) {
    match prepare_session(shared, account, build, previous.as_ref()).await {
        Ok(hooks) => {
            let outcome = run_shell_session(order, &session_env(shared, &hooks)).await;
            (outcome, Some(hooks))
        }
        Err(error) => (Err(error), previous),
    }
}


/// The process-wide worker: like `run_shell_worker`, but the account is resolved and both hooks are built afresh for every session.
pub async fn run_shell_worker_with(
    orders: mpsc::Receiver<VerifiedOpenShell>,
    slot: ShellSlot,
    shared: &ShellShared<'_>,
    account: &str,
    build: BuildFn,
) -> u64 {
    let (handled, _last) = ReceiverStream::new(orders)
        .fold((0, None), |(count, previous), order| {
            let released = &slot;
            async move {
                let (outcome, kept) = run_prepared(order, shared, account, build, previous).await;
                log_outcome(&outcome);
                release_slot(released);
                (count + 1, kept)
            }
        })
        .await;
    handled
}


pub fn shell_queue() -> (mpsc::Sender<VerifiedOpenShell>, mpsc::Receiver<VerifiedOpenShell>) {
    mpsc::channel(SHELL_QUEUE_CAPACITY)
}
