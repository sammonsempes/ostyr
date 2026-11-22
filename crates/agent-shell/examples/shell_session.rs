//! Drives agent-shell sessions over a fake PTY and the real `attach_shell` against a loopback T749 shell route, and prints each end reason.


#[path = "../tests/suite/rig.rs"]
mod rig;


use agent_channel::model::{ShellInput, ShellSinkEvent};
use agent_channel::proto::ShellCloseReason;
use agent_command::model::{Action, Command, KeyClass, NONCE_LENGTH};
use agent_shell::model::{PtyHandle, ShellEnv, ShellOutcome, VerifiedOpenShell};
use agent_shell::session::{attach_fn, run_shell_session};
use rig::{approve, start_platform, Platform, LOOPBACK_NOW};
use std::error::Error;
use std::io::{self, Write};
use std::sync::Mutex;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};
use tokio::time::sleep;
use tokio_stream::wrappers::ReceiverStream;
use tonic::transport::Channel;


const SESSION: &str = "demo-session";


const LONG_LIMIT: u32 = 600;


const SHORT_LIMIT: u32 = 1;


const QUEUE_DEPTH: usize = 16;


const FLOOD_TURNS: u32 = 40;


const FLOOD_STEP_MILLIS: u64 = 100;


const LIFETIME: u64 = 300;


#[cfg(unix)]
const PRIVATE_DIRECTORY_MODE: u32 = 0o700;


struct Fake {
    feed: mpsc::Sender<io::Result<Vec<u8>>>,
    typed: mpsc::Receiver<Vec<u8>>,
    _exit: oneshot::Sender<()>,
}


fn order_with(limits: (u32, u32)) -> Result<VerifiedOpenShell, Box<dyn Error>> {
    let command = Command {
        key_id: "demo-key".to_owned(),
        key_class: KeyClass::Sensitive,
        agent_id: "agent-1".to_owned(),
        tenant: "acme".to_owned(),
        issued_at: LOOPBACK_NOW,
        expires_at: LOOPBACK_NOW + LIFETIME,
        sequence: 1,
        nonce: [0; NONCE_LENGTH],
        action: Action::OpenShell {
            session_id: SESSION.to_owned(),
            asset: "asset-1".to_owned(),
            ticket: "TCK-1".to_owned(),
            requester: "alice@example.org".to_owned(),
            approvers: vec!["bob@example.org".to_owned()],
            max_seconds: limits.0,
            idle_seconds: limits.1,
        },
    };
    Ok(VerifiedOpenShell::try_from(command)?)
}


fn fake_pty() -> (PtyHandle, Fake) {
    let (feed, output) = mpsc::channel(QUEUE_DEPTH);
    let (input, typed) = mpsc::channel(QUEUE_DEPTH);
    let (exit, exited) = oneshot::channel::<()>();
    let handle = PtyHandle {
        output: Box::pin(ReceiverStream::new(output)),
        input,
        exit: Box::pin(async move {
            if exited.await.is_err() {
                std::future::pending::<()>().await;
            }
        }),
    };
    (handle, Fake { feed, typed, _exit: exit })
}


async fn run(channel: Channel, handle: PtyHandle, limits: (u32, u32)) -> Result<ShellOutcome, Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let slot = Mutex::new(Some(handle));
    let env = ShellEnv {
        agent_id: "agent-1".to_owned(),
        store_directory: directory.path().to_path_buf(),
        store_owner: owner_of(directory.path())?,
        store_lock: Mutex::new(()),
        clock: &|| LOOPBACK_NOW,
        dial: &move || {
            let dialled = channel.clone();
            Box::pin(async move { Ok(dialled) })
        },
        spawn: &move |_order| {
            let taken = slot
                .lock()
                .ok()
                .and_then(|mut held| held.take())
                .ok_or_else(|| io::Error::other("spawned twice"));
            Box::pin(std::future::ready(taken))
        },
        attach: &*attach_fn(),
        cleanup: &|| Box::pin(std::future::ready(Ok(0))),
    };
    Ok(run_shell_session(order_with(limits)?, &env).await?)
}


#[cfg(unix)]
fn owner_of(path: &std::path::Path) -> Result<u32, Box<dyn Error>> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE))?;
    Ok(std::fs::metadata(path)?.uid())
}


#[cfg(not(unix))]
fn owner_of(_path: &std::path::Path) -> Result<u32, Box<dyn Error>> {
    Ok(0)
}


fn shown(event: &ShellSinkEvent) -> String {
    match event {
        ShellSinkEvent::Output(bytes) => format!("output {:?}", String::from_utf8_lossy(bytes)),
        other => format!("{other:?}"),
    }
}


async fn next_event(platform: &mut Platform) -> Result<String, Box<dyn Error>> {
    let event = platform.events.recv().await.ok_or("the platform sink closed")?;
    Ok(shown(&event))
}


async fn echo_and_exit(out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let mut platform = start_platform().await?;
    approve(&platform, SESSION)?;
    let (handle, mut fake) = fake_pty();
    let input = platform.input.clone();
    let session = run(platform.channel.clone(), handle, (LONG_LIMIT, LONG_LIMIT));
    let driver = async {
        let banner = next_event(&mut platform).await?;
        writeln!(out, "platform sees: {banner}")?;
        fake.feed.send(Ok(b"hello from the shell\n".to_vec())).await?;
        writeln!(out, "platform sees: {}", next_event(&mut platform).await?)?;
        input.send(ShellInput::Data(b"ls\n".to_vec())).await?;
        writeln!(out, "shell typed: {:?}", fake.typed.recv().await)?;
        drop(fake.feed);
        writeln!(out, "platform sees: {}", next_event(&mut platform).await?)?;
        Ok::<_, Box<dyn Error>>(())
    };
    let (outcome, driven) = tokio::join!(session, driver);
    driven?;
    writeln!(out, "echo and exit: {:?}", outcome?.reason)?;
    Ok(())
}


async fn platform_close(out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let platform = start_platform().await?;
    approve(&platform, SESSION)?;
    let (handle, _fake) = fake_pty();
    let session = run(platform.channel.clone(), handle, (LONG_LIMIT, LONG_LIMIT));
    let closing = async { Ok::<_, Box<dyn Error>>(platform.input.send(ShellInput::Close(ShellCloseReason::UserClose)).await?) };
    let (outcome, closed) = tokio::join!(session, closing);
    closed?;
    writeln!(out, "platform close: {:?}", outcome?.reason)?;
    Ok(())
}


async fn refused_attach(out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let platform = start_platform().await?;
    let (handle, _fake) = fake_pty();
    let outcome = run(platform.channel.clone(), handle, (LONG_LIMIT, LONG_LIMIT)).await?;
    writeln!(out, "refused attach: {:?}, cleanup clean: {}", outcome.reason, outcome.cleanup_clean)?;
    Ok(())
}


async fn max_seconds(out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let platform = start_platform().await?;
    approve(&platform, SESSION)?;
    let (handle, _fake) = fake_pty();
    let outcome = run(platform.channel.clone(), handle, (SHORT_LIMIT, LONG_LIMIT)).await?;
    writeln!(out, "max seconds: {:?}", outcome.reason)?;
    Ok(())
}


async fn idle_with_output_flood(out: &mut impl Write) -> Result<(), Box<dyn Error>> {
    let platform = start_platform().await?;
    approve(&platform, SESSION)?;
    let (handle, fake) = fake_pty();
    let session = run(platform.channel.clone(), handle, (LONG_LIMIT, SHORT_LIMIT));
    let flood = async {
        for _turn in 0..FLOOD_TURNS {
            sleep(Duration::from_millis(FLOOD_STEP_MILLIS)).await;
            if fake.feed.send(Ok(b"noise\n".to_vec())).await.is_err() {
                tracing::info!("the session no longer reads the output");
            }
        }
    };
    let (outcome, ()) = tokio::join!(session, flood);
    writeln!(out, "idle while the shell floods output: {:?}", outcome?.reason)?;
    Ok(())
}


#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let mut out = io::stdout();
    echo_and_exit(&mut out).await?;
    platform_close(&mut out).await?;
    refused_attach(&mut out).await?;
    max_seconds(&mut out).await?;
    idle_with_output_flood(&mut out).await?;
    Ok(())
}
