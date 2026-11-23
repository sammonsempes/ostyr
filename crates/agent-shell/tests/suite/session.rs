use crate::support::{
    default_order, env_of, failing_dial, failing_spawn, fake_pty, fakes_with, forbidden_spawn, hold_script, once_spawn, order_of, recorded,
    scripted_cleanup, Fakes, Script, IDLE_SECONDS, MAX_SECONDS, NOW, SESSION,
};
use crate::types::TestResult;
use agent_channel::model::ShellClientEnd;
use agent_shell::banner::shell_banner;
use agent_shell::error::{ShellError, StoreError};
use agent_shell::model::{EndReason, PtyHandle, StoreEntry, VerifiedOpenShell, MAX_SHELL_SESSION_IDS, STORE_FILE_NAME};
use agent_shell::queue::{new_slot, shell_execute_fn};
use agent_shell::session::{cleanup_verdict, forward_input, input_pipe, run_shell_session, run_shell_worker, shell_queue};
use agent_shell::store::write_entries;
use futures_util::StreamExt;
use std::future::Future;
use std::io;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::time::{sleep, Instant};
use tonic::Code;


const SHORT_MAX: u32 = 100;


const EXPECTED_TYPED: u32 = 3;


const LATE: u64 = 10_000;


const TWICE: u64 = 2;


const SHORT_IDLE: u32 = 60;


const TYPING_STEP: u64 = 30;


const TYPING_TURNS: u64 = 6;


const FLOOD_STEP: u64 = 10;


const FLOOD_TURNS: u64 = 10;


const FLUSH_WAIT: u64 = 5;


const EARLY_INPUT: u64 = 50;


const PAUSE: u64 = 1;


const LEFTOVERS: usize = 2;


const FUTURE: u64 = NOW + 10_000;


const SECOND_SESSION: &str = "session-2";


fn seconds(count: u64) -> Duration {
    Duration::from_secs(count)
}


async fn timed<Output>(work: impl Future<Output = Output>) -> (Output, Duration) {
    let started = Instant::now();
    let output = work.await;
    (output, started.elapsed())
}


fn finishing(end: ShellClientEnd) -> Script {
    Script::Finish(Ok(end))
}


fn calls_of(fakes: &Fakes) -> Result<Vec<&'static str>, Box<dyn std::error::Error>> {
    recorded(&fakes.calls)
}


fn holding_fakes(handle: PtyHandle, script: Script) -> Result<Fakes, Box<dyn std::error::Error>> {
    fakes_with(move |calls| once_spawn(calls, handle), script)
}


#[tokio::test(start_paused = true)]
async fn a_session_cleans_up_before_and_after_and_names_its_end() -> TestResult {
    let pty = fake_pty();
    let fakes = holding_fakes(pty.handle, finishing(ShellClientEnd::ServerClosed))?;
    let outcome = run_shell_session(default_order()?, &env_of(&fakes)?).await?;
    assert_eq!(outcome.session_id, SESSION);
    assert_eq!(outcome.reason, EndReason::Attached(ShellClientEnd::ServerClosed));
    assert!(outcome.cleanup_clean);
    assert_eq!(calls_of(&fakes)?, vec!["cleanup", "dial", "spawn", "attach", "cleanup"]);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_banner_leads_the_stream_and_data_goes_both_ways() -> TestResult {
    let mut pty = fake_pty();
    let (script, handover) = hold_script();
    let fakes = holding_fakes(pty.handle, script)?;
    let order = default_order()?;
    let banner = shell_banner(&order, "agent-1");
    let env = env_of(&fakes)?;
    let session = run_shell_session(order, &env);
    let feed = pty.feed;
    let driver = async {
        let (mut reader, mut writer) = handover.await?;
        let first = reader.next().await.ok_or("no banner")??;
        assert_eq!(first, banner);
        feed.send(Ok(b"hello".to_vec())).await?;
        let second = reader.next().await.ok_or("no output")??;
        assert_eq!(second, b"hello".to_vec());
        writer.write_all(b"ls\n").await?;
        writer.flush().await?;
        let typed = pty.typed.recv().await.ok_or("no input")?;
        assert_eq!(typed, b"ls\n".to_vec());
        pty.exit.send(()).map_err(|()| "exit receiver gone")?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (outcome, driven) = tokio::join!(session, driver);
    driven?;
    assert_eq!(outcome?.reason, EndReason::ShellExited);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn max_seconds_ends_the_session_while_the_platform_keeps_typing() -> TestResult {
    let pty = fake_pty();
    let (script, handover) = hold_script();
    let fakes = holding_fakes(pty.handle, script)?;
    let env = env_of(&fakes)?;
    let session = timed(run_shell_session(order_of(SESSION, SHORT_MAX, SHORT_IDLE)?, &env));
    let driver = async {
        let (_reader, mut writer) = handover.await?;
        let mut accepted = 0;
        let mut open = true;
        for _turn in 0..TYPING_TURNS {
            sleep(seconds(TYPING_STEP)).await;
            open = open && writer.write_all(b"x").await.is_ok();
            accepted += u32::from(open);
        }
        Ok::<_, Box<dyn std::error::Error>>(accepted)
    };
    let ((outcome, elapsed), accepted) = tokio::join!(session, driver);
    assert_eq!(outcome?.reason, EndReason::MaxSeconds);
    assert_eq!(elapsed, seconds(u64::from(SHORT_MAX)));
    assert_eq!(accepted?, EXPECTED_TYPED);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn idle_seconds_ends_the_session_while_the_shell_floods_output() -> TestResult {
    let pty = fake_pty();
    let sink = Arc::new(Mutex::new(Vec::new()));
    let fakes = holding_fakes(pty.handle, Script::Drain(Arc::clone(&sink)))?;
    let env = env_of(&fakes)?;
    let session = timed(run_shell_session(order_of(SESSION, MAX_SECONDS, SHORT_IDLE)?, &env));
    let feed = pty.feed;
    let flood = async {
        for _turn in 0..FLOOD_TURNS {
            sleep(seconds(FLOOD_STEP)).await;
            if feed.send(Ok(b"noise".to_vec())).await.is_err() {
                tracing::info!("the session no longer reads the output");
            }
        }
    };
    let ((outcome, elapsed), ()) = tokio::join!(session, flood);
    assert_eq!(outcome?.reason, EndReason::Idle);
    assert_eq!(elapsed, seconds(u64::from(SHORT_IDLE)));
    assert!(sink.lock().map_err(|_poisoned| "poisoned")?.ends_with(b"noise"));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn only_the_platform_input_refreshes_the_idle_timer() -> TestResult {
    let pty = fake_pty();
    let (script, handover) = hold_script();
    let fakes = holding_fakes(pty.handle, script)?;
    let env = env_of(&fakes)?;
    let session = run_shell_session(order_of(SESSION, MAX_SECONDS, SHORT_IDLE)?, &env);
    let started = Instant::now();
    let driver = async {
        let (_reader, mut writer) = handover.await?;
        sleep(seconds(EARLY_INPUT)).await;
        writer.write_all(b"x").await?;
        writer.flush().await?;
        Ok::<_, Box<dyn std::error::Error>>(writer)
    };
    let (outcome, writer) = tokio::join!(session, driver);
    drop(writer?);
    assert_eq!(outcome?.reason, EndReason::Idle);
    assert_eq!(started.elapsed(), seconds(EARLY_INPUT + u64::from(SHORT_IDLE)));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_refused_attach_ends_the_session_cleans_up_and_burns_the_id() -> TestResult {
    let pty = fake_pty();
    let fakes = holding_fakes(pty.handle, Script::Finish(Err(Code::PermissionDenied)))?;
    let outcome = run_shell_session(default_order()?, &env_of(&fakes)?).await?;
    assert_eq!(outcome.reason, EndReason::AttachFailed);
    assert!(outcome.cleanup_clean);
    assert_eq!(calls_of(&fakes)?, vec!["cleanup", "dial", "spawn", "attach", "cleanup"]);
    let mut again = fakes_with(forbidden_spawn_of, finishing(ShellClientEnd::Dead))?;
    again.directory = fakes.directory;
    let refused = run_shell_session(default_order()?, &env_of(&again)?).await;
    assert!(matches!(refused, Err(ShellError::Store(StoreError::Replayed))));
    assert_eq!(calls_of(&again)?, vec!["cleanup"]);
    Ok(())
}


fn forbidden_spawn_of(calls: &crate::types::Calls) -> Box<agent_shell::types::SpawnFn> {
    forbidden_spawn(calls)
}


#[tokio::test(start_paused = true)]
async fn a_dead_stream_is_named_and_cleaned_up() -> TestResult {
    let pty = fake_pty();
    let fakes = holding_fakes(pty.handle, finishing(ShellClientEnd::Dead))?;
    let outcome = run_shell_session(default_order()?, &env_of(&fakes)?).await?;
    assert_eq!(outcome.reason, EndReason::Attached(ShellClientEnd::Dead));
    assert_eq!(calls_of(&fakes)?.last(), Some(&"cleanup"));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_shell_exit_lets_the_last_output_reach_the_attach() -> TestResult {
    let pty = fake_pty();
    let sink = Arc::new(Mutex::new(Vec::new()));
    let fakes = holding_fakes(pty.handle, Script::Drain(Arc::clone(&sink)))?;
    let env = env_of(&fakes)?;
    let session = run_shell_session(default_order()?, &env);
    let started = Instant::now();
    let driver = async {
        pty.feed.send(Ok(b"last words".to_vec())).await?;
        pty.exit.send(()).map_err(|()| "exit receiver gone")?;
        sleep(seconds(PAUSE)).await;
        drop(pty.feed);
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (outcome, driven) = tokio::join!(session, driver);
    driven?;
    assert_eq!(outcome?.reason, EndReason::ShellExited);
    assert_eq!(started.elapsed(), seconds(PAUSE));
    assert!(sink.lock().map_err(|_poisoned| "poisoned")?.ends_with(b"last words"));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn an_attach_that_outlives_the_exit_is_cut_after_the_flush_time() -> TestResult {
    let pty = fake_pty();
    let (script, _handover) = hold_script();
    let fakes = holding_fakes(pty.handle, script)?;
    let env = env_of(&fakes)?;
    let session = run_shell_session(default_order()?, &env);
    let started = Instant::now();
    pty.exit.send(()).map_err(|()| "exit receiver gone")?;
    let outcome = session.await?;
    assert_eq!(outcome.reason, EndReason::ShellExited);
    assert_eq!(started.elapsed(), seconds(FLUSH_WAIT));
    drop(pty.feed);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_shell_that_no_longer_takes_input_ends_the_session() -> TestResult {
    let pty = fake_pty();
    let (script, handover) = hold_script();
    let fakes = holding_fakes(pty.handle, script)?;
    let env = env_of(&fakes)?;
    let session = run_shell_session(default_order()?, &env);
    let driver = async {
        let (_reader, mut writer) = handover.await?;
        drop(pty.typed);
        writer.write_all(b"x").await?;
        writer.flush().await?;
        Ok::<_, Box<dyn std::error::Error>>(writer)
    };
    let (outcome, writer) = tokio::join!(session, driver);
    drop(writer?);
    assert_eq!(outcome?.reason, EndReason::ShellGone);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_closed_input_does_not_end_the_session_by_itself() -> TestResult {
    let pty = fake_pty();
    let fakes = holding_fakes(pty.handle, Script::DropWriterThenPend)?;
    let started = Instant::now();
    let outcome = run_shell_session(order_of(SESSION, SHORT_MAX, SHORT_IDLE)?, &env_of(&fakes)?).await?;
    assert_eq!(outcome.reason, EndReason::MaxSeconds);
    assert_eq!(started.elapsed(), seconds(u64::from(SHORT_MAX)));
    drop(pty.feed);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_command_past_its_expiry_is_refused_before_anything_runs() -> TestResult {
    let fakes = fakes_with(forbidden_spawn_of, finishing(ShellClientEnd::Dead))?;
    let mut late = fakes;
    late.clock = crate::support::fixed_clock(NOW + LATE);
    let refused = run_shell_session(default_order()?, &env_of(&late)?).await;
    assert!(matches!(refused, Err(ShellError::Expired)));
    assert!(calls_of(&late)?.is_empty());
    assert!(!late.directory.path().join(STORE_FILE_NAME).exists());
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn leftovers_or_a_failed_cleanup_refuse_the_session_before_the_spawn() -> TestResult {
    let mut fakes = fakes_with(forbidden_spawn_of, finishing(ShellClientEnd::Dead))?;
    fakes.cleanup = scripted_cleanup(&fakes.calls, vec![Some(LEFTOVERS)]);
    let refused = run_shell_session(default_order()?, &env_of(&fakes)?).await;
    assert!(matches!(refused, Err(ShellError::Leftover(LEFTOVERS))));
    fakes.cleanup = scripted_cleanup(&fakes.calls, vec![None]);
    let failed = run_shell_session(default_order()?, &env_of(&fakes)?).await;
    assert!(matches!(failed, Err(ShellError::Cleanup(_))));
    assert_eq!(calls_of(&fakes)?, vec!["cleanup", "cleanup"]);
    assert!(!fakes.directory.path().join(STORE_FILE_NAME).exists());
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_cleanup_after_the_end_that_leaves_something_is_reported() -> TestResult {
    let pty = fake_pty();
    let mut fakes = holding_fakes(pty.handle, finishing(ShellClientEnd::ServerClosed))?;
    fakes.cleanup = scripted_cleanup(&fakes.calls, vec![Some(0), Some(1)]);
    let outcome = run_shell_session(default_order()?, &env_of(&fakes)?).await?;
    assert!(!outcome.cleanup_clean);
    let again = fake_pty();
    let mut failing = holding_fakes(again.handle, finishing(ShellClientEnd::ServerClosed))?;
    failing.cleanup = scripted_cleanup(&failing.calls, vec![Some(0), None]);
    let failed = run_shell_session(order_of(SECOND_SESSION, MAX_SECONDS, IDLE_SECONDS)?, &env_of(&failing)?).await?;
    assert!(!failed.cleanup_clean);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_replayed_session_id_is_refused_after_a_restart_and_nothing_spawns() -> TestResult {
    let pty = fake_pty();
    let first = holding_fakes(pty.handle, finishing(ShellClientEnd::ServerClosed))?;
    run_shell_session(default_order()?, &env_of(&first)?).await?;
    let mut restarted = fakes_with(forbidden_spawn_of, finishing(ShellClientEnd::ServerClosed))?;
    restarted.directory = first.directory;
    let refused = run_shell_session(default_order()?, &env_of(&restarted)?).await;
    assert!(matches!(refused, Err(ShellError::Store(StoreError::Replayed))));
    assert_eq!(calls_of(&restarted)?, vec!["cleanup"]);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_double_open_shell_of_one_id_runs_one_session() -> TestResult {
    let pty = fake_pty();
    let fakes = holding_fakes(pty.handle, finishing(ShellClientEnd::ServerClosed))?;
    let env = env_of(&fakes)?;
    let (first, second) = tokio::join!(run_shell_session(default_order()?, &env), run_shell_session(default_order()?, &env));
    assert_eq!([first.is_ok(), second.is_ok()].iter().filter(|accepted| **accepted).count(), 1);
    let refused = first.err().or(second.err());
    assert!(matches!(refused, Some(ShellError::Store(StoreError::Replayed))));
    assert_eq!(calls_of(&fakes)?.iter().filter(|call| **call == "spawn").count(), 1);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_full_store_refuses_the_session_and_nothing_spawns() -> TestResult {
    let fakes = fakes_with(forbidden_spawn_of, finishing(ShellClientEnd::Dead))?;
    let entries: Vec<StoreEntry> = (0..MAX_SHELL_SESSION_IDS)
        .map(|index| StoreEntry {
            session_id: format!("old-{index}"),
            expires_at: FUTURE,
        })
        .collect();
    write_entries(&fakes.directory.path().join(STORE_FILE_NAME), &entries)?;
    let refused = run_shell_session(default_order()?, &env_of(&fakes)?).await;
    assert!(matches!(refused, Err(ShellError::Store(StoreError::Full))));
    assert_eq!(calls_of(&fakes)?, vec!["cleanup"]);
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_failed_dial_spawns_nothing_but_burns_the_id() -> TestResult {
    let mut fakes = fakes_with(forbidden_spawn_of, finishing(ShellClientEnd::Dead))?;
    fakes.dial = failing_dial(&fakes.calls);
    let refused = run_shell_session(default_order()?, &env_of(&fakes)?).await;
    assert!(matches!(refused, Err(ShellError::Dial(_))));
    assert_eq!(calls_of(&fakes)?, vec!["cleanup", "dial"]);
    let again = run_shell_session(default_order()?, &env_of(&fakes)?).await;
    assert!(matches!(again, Err(ShellError::Store(StoreError::Replayed))));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn a_failed_spawn_is_named_and_cleaned_up() -> TestResult {
    let fakes = fakes_with(failing_spawn_of, finishing(ShellClientEnd::Dead))?;
    let refused = run_shell_session(default_order()?, &env_of(&fakes)?).await;
    assert!(matches!(refused, Err(ShellError::Spawn(_))));
    assert_eq!(calls_of(&fakes)?, vec!["cleanup", "dial", "spawn", "cleanup"]);
    Ok(())
}


fn failing_spawn_of(calls: &crate::types::Calls) -> Box<agent_shell::types::SpawnFn> {
    failing_spawn(calls)
}


#[tokio::test(start_paused = true)]
async fn a_poisoned_store_lock_does_not_stop_the_next_session() -> TestResult {
    let pty = fake_pty();
    let fakes = holding_fakes(pty.handle, finishing(ShellClientEnd::ServerClosed))?;
    let env = env_of(&fakes)?;
    let failed = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let _held = env.store_lock.lock();
                std::panic::resume_unwind(Box::new("poison the store lock"))
            })
            .join()
            .is_err()
    });
    assert!(failed);
    assert!(env.store_lock.is_poisoned());
    let outcome = run_shell_session(default_order()?, &env).await?;
    assert_eq!(outcome.reason, EndReason::Attached(ShellClientEnd::ServerClosed));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_worker_runs_queued_sessions_and_frees_the_slot_each_time() -> TestResult {
    let pty = fake_pty();
    let fakes = holding_fakes(pty.handle, finishing(ShellClientEnd::ServerClosed))?;
    let env = env_of(&fakes)?;
    let slot = new_slot();
    let (queue, orders) = shell_queue();
    let execute = shell_execute_fn(Arc::clone(&slot), queue);
    let worker = run_shell_worker(orders, Arc::clone(&slot), &env);
    let driver = async {
        let accepted = execute(crate::support::command_of(crate::support::open_action(
            SESSION,
            MAX_SECONDS,
            IDLE_SECONDS,
        )));
        let refused = execute(crate::support::command_of(crate::support::open_action(
            SECOND_SESSION,
            MAX_SECONDS,
            IDLE_SECONDS,
        )));
        drop(execute);
        (accepted, refused)
    };
    let (handled, (accepted, refused)) = tokio::join!(worker, driver);
    assert!(accepted);
    assert!(!refused);
    assert_eq!(handled, 1);
    assert!(!slot.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}


#[tokio::test(start_paused = true)]
async fn the_worker_logs_and_survives_a_refused_session() -> TestResult {
    let pty = fake_pty();
    let fakes = holding_fakes(pty.handle, finishing(ShellClientEnd::ServerClosed))?;
    let env = env_of(&fakes)?;
    let (queue, orders) = shell_queue();
    let worker = run_shell_worker(orders, new_slot(), &env);
    let driver = async {
        let twice: Vec<VerifiedOpenShell> = vec![default_order()?, default_order()?];
        for order in twice {
            queue.send(order).await?;
        }
        drop(queue);
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    let (handled, driven) = tokio::join!(worker, driver);
    driven?;
    assert_eq!(handled, TWICE);
    Ok(())
}


#[test]
fn the_cleanup_verdict_names_each_outcome() -> TestResult {
    assert!(cleanup_verdict(Ok(0)).is_ok());
    assert!(matches!(cleanup_verdict(Ok(LEFTOVERS)), Err(ShellError::Leftover(LEFTOVERS))));
    assert!(matches!(cleanup_verdict(Err(io::Error::other("x"))), Err(ShellError::Cleanup(_))));
    Ok(())
}


#[tokio::test]
async fn the_input_pipe_reports_a_shell_input_that_is_gone() -> TestResult {
    let (mut writer, chunks) = input_pipe();
    drop(chunks);
    let failed = writer.write_all(b"x").await;
    assert_eq!(failed.err().map(|error| error.kind()), Some(io::ErrorKind::BrokenPipe));
    Ok(())
}


#[tokio::test]
async fn an_input_that_cannot_be_read_ends_the_session_as_gone() -> TestResult {
    let (input, _typed) = tokio::sync::mpsc::channel(1);
    let ended = forward_input(&input, Ok(Err(io::Error::other("broken")))).await;
    assert_eq!(ended, Err(EndReason::ShellGone));
    Ok(())
}
