use crate::types::{Calls, Handover};
use agent_channel::error::ChannelError;
use agent_channel::model::ShellClientEnd;
use agent_channel::types::{ShellReader, ShellWriter};
use agent_command::model::{Action, Command, KeyClass, NONCE_LENGTH};
use agent_shell::model::{PtyHandle, ShellEnv, VerifiedOpenShell};
use agent_shell::types::{AttachFn, CleanupFn, ClockFn, DialFn, SpawnFn};
use futures_util::StreamExt;
use std::error::Error;
use std::io;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;
use tokio::sync::{mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Endpoint;
use tonic::Code;


pub const NOW: u64 = 1_000_000;


pub const LIFETIME: u64 = 300;


pub const MAX_SECONDS: u32 = 600;


pub const IDLE_SECONDS: u32 = 60;


pub const SESSION: &str = "session-1";


pub const AGENT: &str = "agent-1";


pub const FEED_DEPTH: usize = 16;


#[cfg(unix)]
pub const PRIVATE_DIRECTORY_MODE: u32 = 0o700;


#[cfg(unix)]
pub const PRIVATE_FILE_MODE: u32 = 0o600;


pub const LAZY_ADDRESS: &str = "http://127.0.0.1:1";


pub fn new_calls() -> Calls {
    Arc::new(Mutex::new(Vec::new()))
}


pub fn recorded(calls: &Calls) -> Result<Vec<&'static str>, Box<dyn Error>> {
    Ok(calls.lock().map_err(|_poisoned| "calls poisoned")?.clone())
}


pub fn note(calls: &Calls, call: &'static str) {
    if let Ok(mut held) = calls.lock() {
        held.push(call);
    }
}


pub fn open_action(session: &str, max_seconds: u32, idle_seconds: u32) -> Action {
    Action::OpenShell {
        session_id: session.to_owned(),
        asset: "asset-1".to_owned(),
        ticket: "TCK-1".to_owned(),
        requester: "alice@example.org".to_owned(),
        approvers: vec!["bob@example.org".to_owned(), "carol@example.org".to_owned()],
        max_seconds,
        idle_seconds,
    }
}


pub fn command_of(action: Action) -> Command {
    Command {
        key_id: "key-1".to_owned(),
        key_class: KeyClass::Sensitive,
        agent_id: AGENT.to_owned(),
        tenant: "acme".to_owned(),
        issued_at: NOW,
        expires_at: NOW + LIFETIME,
        sequence: 1,
        nonce: [0; NONCE_LENGTH],
        action,
    }
}


pub fn order_of(session: &str, max_seconds: u32, idle_seconds: u32) -> Result<VerifiedOpenShell, Box<dyn Error>> {
    Ok(VerifiedOpenShell::try_from(command_of(open_action(session, max_seconds, idle_seconds)))?)
}


pub fn default_order() -> Result<VerifiedOpenShell, Box<dyn Error>> {
    order_of(SESSION, MAX_SECONDS, IDLE_SECONDS)
}


#[cfg(unix)]
pub fn owner_of(path: &Path) -> Result<u32, Box<dyn Error>> {
    use std::os::unix::fs::MetadataExt;
    Ok(std::fs::metadata(path)?.uid())
}


#[cfg(not(unix))]
pub fn owner_of(_path: &Path) -> Result<u32, Box<dyn Error>> {
    Ok(0)
}


pub struct Pty {
    pub handle: PtyHandle,
    pub feed: mpsc::Sender<io::Result<Vec<u8>>>,
    pub typed: mpsc::Receiver<Vec<u8>>,
    pub exit: oneshot::Sender<()>,
}


pub fn fake_pty() -> Pty {
    let (feed, output) = mpsc::channel(FEED_DEPTH);
    let (input, typed) = mpsc::channel(FEED_DEPTH);
    let (exit, exited) = oneshot::channel();
    Pty {
        handle: PtyHandle {
            output: Box::pin(ReceiverStream::new(output)),
            input,
            exit: Box::pin(async move {
                if exited.await.is_err() {
                    std::future::pending::<()>().await;
                }
            }),
        },
        feed,
        typed,
        exit,
    }
}


pub fn once_spawn(calls: &Calls, handle: PtyHandle) -> Box<SpawnFn> {
    let slot = Mutex::new(Some(handle));
    let spawned = Arc::clone(calls);
    Box::new(move |_order| {
        note(&spawned, "spawn");
        slot.lock()
            .ok()
            .and_then(|mut held| held.take())
            .ok_or_else(|| io::Error::other("spawned twice"))
    })
}


pub fn failing_spawn(calls: &Calls) -> Box<SpawnFn> {
    let spawned = Arc::clone(calls);
    Box::new(move |_order| {
        note(&spawned, "spawn");
        Err(io::Error::other("no pty"))
    })
}


pub fn forbidden_spawn(calls: &Calls) -> Box<SpawnFn> {
    let spawned = Arc::clone(calls);
    Box::new(move |_order| {
        note(&spawned, "spawn-forbidden");
        Err(io::Error::other("must not spawn"))
    })
}


pub fn fixed_clock(now: u64) -> Box<ClockFn> {
    Box::new(move || now)
}


pub fn lazy_dial(calls: &Calls) -> Box<DialFn> {
    let dialled = Arc::clone(calls);
    Box::new(move || {
        note(&dialled, "dial");
        Box::pin(async { Ok(Endpoint::from_static(LAZY_ADDRESS).connect_lazy()) })
    })
}


pub fn failing_dial(calls: &Calls) -> Box<DialFn> {
    let dialled = Arc::clone(calls);
    Box::new(move || {
        note(&dialled, "dial");
        Box::pin(async { Err(ChannelError::Status(Box::new(tonic::Status::unavailable("down")))) })
    })
}


/// Each call of the cleanup answers the next entry (`None` is an error); the last entry repeats.
pub fn scripted_cleanup(calls: &Calls, answers: Vec<Option<usize>>) -> Box<CleanupFn> {
    let cleaned = Arc::clone(calls);
    let position = AtomicUsize::new(0);
    Box::new(move || {
        note(&cleaned, "cleanup");
        let index = position.fetch_add(1, Ordering::SeqCst).min(answers.len().saturating_sub(1));
        match answers.get(index).copied().flatten() {
            Some(left) => Ok(left),
            None => Err(io::Error::other("cleanup failed")),
        }
    })
}


pub fn clean_cleanup(calls: &Calls) -> Box<CleanupFn> {
    scripted_cleanup(calls, vec![Some(0)])
}


#[derive(Clone)]
pub enum Script {
    Hold(Handover),
    Finish(Result<ShellClientEnd, Code>),
    DropWriterThenPend,
    Drain(Arc<Mutex<Vec<u8>>>),
}


pub fn hold_script() -> (Script, oneshot::Receiver<(ShellReader, ShellWriter)>) {
    let (sender, receiver) = oneshot::channel();
    (Script::Hold(Arc::new(Mutex::new(Some(sender)))), receiver)
}


pub fn scripted_attach(calls: &Calls, script: Script) -> Box<AttachFn> {
    let attached = Arc::clone(calls);
    Box::new(move |_channel, _session, reader, writer| {
        note(&attached, "attach");
        let behaviour = script.clone();
        Box::pin(async move { play(behaviour, reader, writer).await })
    })
}


pub async fn play(script: Script, reader: ShellReader, writer: ShellWriter) -> Result<ShellClientEnd, ChannelError> {
    match script {
        Script::Hold(handover) => {
            let sender = handover.lock().ok().and_then(|mut held| held.take());
            if let Some(taker) = sender {
                if taker.send((reader, writer)).is_err() {
                    tracing::warn!("handover receiver gone");
                }
            }
            std::future::pending::<Result<ShellClientEnd, ChannelError>>().await
        }
        Script::Finish(Ok(end)) => Ok(end),
        Script::Finish(Err(code)) => Err(ChannelError::Status(Box::new(tonic::Status::new(code, "refused")))),
        Script::DropWriterThenPend => {
            drop(writer);
            std::future::pending::<Result<ShellClientEnd, ChannelError>>().await
        }
        Script::Drain(sink) => {
            reader
                .for_each(|chunk| {
                    if let (Ok(bytes), Ok(mut held)) = (chunk, sink.lock()) {
                        held.extend(bytes);
                    }
                    std::future::ready(())
                })
                .await;
            drop(writer);
            Ok(ShellClientEnd::StreamEnded)
        }
    }
}


pub struct Fakes {
    pub calls: Calls,
    pub clock: Box<ClockFn>,
    pub dial: Box<DialFn>,
    pub spawn: Box<SpawnFn>,
    pub attach: Box<AttachFn>,
    pub cleanup: Box<CleanupFn>,
    pub directory: TempDir,
}


pub fn fakes_with(spawn: impl FnOnce(&Calls) -> Box<SpawnFn>, script: Script) -> Result<Fakes, Box<dyn Error>> {
    let calls = new_calls();
    Ok(Fakes {
        clock: fixed_clock(NOW),
        dial: lazy_dial(&calls),
        spawn: spawn(&calls),
        attach: scripted_attach(&calls, script),
        cleanup: clean_cleanup(&calls),
        directory: private_tempdir()?,
        calls,
    })
}


pub fn env_of<'env>(fakes: &'env Fakes) -> Result<ShellEnv<'env>, Box<dyn Error>> {
    Ok(ShellEnv {
        agent_id: AGENT.to_owned(),
        store_directory: fakes.directory.path().to_path_buf(),
        store_owner: owner_of(fakes.directory.path())?,
        store_lock: Mutex::new(()),
        clock: &*fakes.clock,
        dial: &*fakes.dial,
        spawn: &*fakes.spawn,
        attach: &*fakes.attach,
        cleanup: &*fakes.cleanup,
    })
}


#[cfg(unix)]
pub fn private_tempdir() -> Result<TempDir, Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    let directory = tempfile::tempdir()?;
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?;
    Ok(directory)
}


#[cfg(not(unix))]
pub fn private_tempdir() -> Result<TempDir, Box<dyn Error>> {
    Ok(tempfile::tempdir()?)
}


#[cfg(unix)]
pub fn write_private(path: &Path, content: &[u8]) -> Result<(), Box<dyn Error>> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, content)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
    Ok(())
}
