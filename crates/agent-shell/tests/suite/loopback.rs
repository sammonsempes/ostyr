use crate::rig::{approve, start_platform, Platform, LOOPBACK_NOW};
use crate::support::{
    clean_cleanup, default_order, env_of, fake_pty, fixed_clock, new_calls, once_spawn, order_of, recorded, Fakes, IDLE_SECONDS, SESSION,
};
use crate::types::TestResult;
use agent_channel::model::{AgentCloseReason, ShellClientEnd, ShellEnd, ShellInput, ShellSinkEvent};
use agent_channel::proto::ShellCloseReason;
use agent_shell::banner::shell_banner;
use agent_shell::model::{EndReason, ShellOutcome};
use agent_shell::session::{attach_fn, run_shell_session};
use agent_shell::types::DialFn;
use std::error::Error;
use std::time::Duration;
use tokio::time::{sleep, timeout};


const SHORT_LIMIT: u32 = 1;


const LONG_LIMIT: u32 = 600;


const WAIT_SECONDS: u64 = 60;


const FLOOD_TURNS: u32 = 40;


const FLOOD_STEP_MILLIS: u64 = 100;


fn dial_to(platform: &Platform) -> Box<DialFn> {
    let channel = platform.channel.clone();
    Box::new(move || {
        let ready_channel = channel.clone();
        Box::pin(async move { Ok(ready_channel) })
    })
}


fn real_fakes(platform: &Platform, handle: agent_shell::model::PtyHandle) -> Result<Fakes, Box<dyn Error>> {
    let calls = new_calls();
    Ok(Fakes {
        clock: fixed_clock(LOOPBACK_NOW),
        dial: dial_to(platform),
        spawn: once_spawn(&calls, handle),
        attach: attach_fn(),
        cleanup: clean_cleanup(&calls),
        directory: crate::support::private_tempdir()?,
        store_lock: std::sync::Mutex::new(()),
        calls,
    })
}


async fn next_event(platform: &mut Platform) -> Result<ShellSinkEvent, Box<dyn Error>> {
    timeout(Duration::from_secs(WAIT_SECONDS), platform.events.recv())
        .await?
        .ok_or_else(|| "the platform sink closed".into())
}


async fn outcome_of(fakes: &Fakes, limits: (u32, u32)) -> Result<ShellOutcome, Box<dyn Error>> {
    let env = env_of(fakes)?;
    let order = order_of(SESSION, limits.0, limits.1)?;
    Ok(timeout(Duration::from_secs(WAIT_SECONDS), run_shell_session(order, &env)).await??)
}


#[tokio::test]
async fn the_banner_and_the_data_cross_the_real_attach_both_ways() -> TestResult {
    let mut platform = start_platform().await?;
    approve(&platform, SESSION)?;
    let mut pty = fake_pty();
    let fakes = real_fakes(&platform, pty.handle)?;
    let session = outcome_of(&fakes, (LONG_LIMIT, IDLE_SECONDS));
    let banner = shell_banner(&default_order()?, "agent-1");
    let input = platform.input.clone();
    let feed = pty.feed;
    let driver = async {
        assert_eq!(next_event(&mut platform).await?, ShellSinkEvent::Output(banner));
        feed.send(Ok(b"hello".to_vec())).await?;
        assert_eq!(next_event(&mut platform).await?, ShellSinkEvent::Output(b"hello".to_vec()));
        input.send(ShellInput::Data(b"ls\n".to_vec())).await?;
        assert_eq!(pty.typed.recv().await, Some(b"ls\n".to_vec()));
        drop(feed);
        assert_eq!(
            next_event(&mut platform).await?,
            ShellSinkEvent::Ended(ShellEnd::AgentClosed(AgentCloseReason::Exited))
        );
        Ok::<_, Box<dyn Error>>(())
    };
    let (outcome, driven) = tokio::join!(session, driver);
    driven?;
    assert_eq!(outcome?.reason, EndReason::Attached(ShellClientEnd::StreamEnded));
    Ok(())
}


#[tokio::test]
async fn a_close_from_the_platform_ends_the_session() -> TestResult {
    let platform = start_platform().await?;
    approve(&platform, SESSION)?;
    let pty = fake_pty();
    let fakes = real_fakes(&platform, pty.handle)?;
    let session = outcome_of(&fakes, (LONG_LIMIT, IDLE_SECONDS));
    let closing = async {
        platform.input.send(ShellInput::Close(ShellCloseReason::UserClose)).await?;
        Ok::<_, Box<dyn Error>>(())
    };
    let (outcome, closed) = tokio::join!(session, closing);
    closed?;
    assert_eq!(outcome?.reason, EndReason::Attached(ShellClientEnd::ServerClosed));
    assert_eq!(recorded(&fakes.calls)?.last(), Some(&"cleanup"));
    drop(pty.feed);
    Ok(())
}


#[tokio::test]
async fn an_attach_the_platform_refuses_ends_as_failed_and_cleans_up() -> TestResult {
    let platform = start_platform().await?;
    let pty = fake_pty();
    let fakes = real_fakes(&platform, pty.handle)?;
    let outcome = outcome_of(&fakes, (LONG_LIMIT, IDLE_SECONDS)).await?;
    assert_eq!(outcome.reason, EndReason::AttachFailed);
    assert!(outcome.cleanup_clean);
    assert_eq!(recorded(&fakes.calls)?, vec!["cleanup", "spawn", "cleanup"]);
    drop(pty.feed);
    Ok(())
}


#[tokio::test]
async fn max_seconds_ends_a_real_attach() -> TestResult {
    let platform = start_platform().await?;
    approve(&platform, SESSION)?;
    let pty = fake_pty();
    let fakes = real_fakes(&platform, pty.handle)?;
    let outcome = outcome_of(&fakes, (SHORT_LIMIT, IDLE_SECONDS)).await?;
    assert_eq!(outcome.reason, EndReason::MaxSeconds);
    drop(pty.feed);
    Ok(())
}


#[tokio::test]
async fn idle_seconds_ends_a_real_attach_while_the_shell_floods_output() -> TestResult {
    let platform = start_platform().await?;
    approve(&platform, SESSION)?;
    let pty = fake_pty();
    let fakes = real_fakes(&platform, pty.handle)?;
    let session = outcome_of(&fakes, (LONG_LIMIT, SHORT_LIMIT));
    let feed = pty.feed;
    let flood = async {
        for _turn in 0..FLOOD_TURNS {
            sleep(Duration::from_millis(FLOOD_STEP_MILLIS)).await;
            if feed.send(Ok(b"noise".to_vec())).await.is_err() {
                tracing::info!("the session no longer reads the output");
            }
        }
    };
    let (outcome, ()) = tokio::join!(session, flood);
    assert_eq!(outcome?.reason, EndReason::Idle);
    Ok(())
}
