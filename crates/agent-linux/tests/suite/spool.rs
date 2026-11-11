use crate::sensor::{environment, settings, show_text};
use crate::support::{append, lines, scoped_logging, setup, EXEC, LINE_LIMIT};
use crate::types::TestResult;
use agent_channel::app::shared_log_audit;
use agent_linux::follow::poll;
use agent_linux::model::SourceSettings;
use agent_linux::sensor::{tick, SensorEnv, Supervisor};
use agent_linux::spool::append_locked;
use agent_linux::types::SpoolLock;
use core_audit::log::open_file_log;
use std::fs;
use std::sync::{Arc, Barrier};
use std::thread::scope;
use tempfile::tempdir;


const WRITERS: usize = 2;


const CALLS: usize = 300;


const POLLS: usize = 40;


const EXPORT_LINES: usize = 2_000;


const LINES_PER_POLL: u64 = 50;


const TICKS: u64 = 40;


const TICK_STEP: u64 = 100;


const PARITY: u64 = 2;


#[test]
fn two_writers_holding_the_lock_leave_every_line_whole() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let lock = SpoolLock::default();
    let barrier = Barrier::new(WRITERS);
    let outcomes = scope(|workers| {
        (0..WRITERS)
            .map(|writer| {
                let (spool_ref, lock_ref, barrier_ref) = (&spool, &lock, &barrier);
                workers.spawn(move || {
                    barrier_ref.wait();
                    (0..CALLS).try_for_each(|index| append_locked(lock_ref, std::iter::once(Ok(format!("{writer}-{index}"))), spool_ref).map(|_| ()))
                })
            })
            .collect::<Vec<_>>()
            .into_iter()
            .map(|worker| worker.join().map_err(|_| "a writer panicked"))
            .collect::<Vec<_>>()
    });
    outcomes
        .into_iter()
        .try_for_each(|outcome| outcome?.map_err(Box::<dyn std::error::Error>::from))?;
    assert_eq!(lines(&spool)?.len(), WRITERS * CALLS);
    Ok(())
}


#[tokio::test]
async fn the_source_and_the_sensor_share_one_spool_and_every_line_parses() -> TestResult {
    let _log = scoped_logging();
    let mut source = setup()?;
    let sensor_dir = tempdir()?;
    let env = SensorEnv {
        spool: source.paths.spool.clone(),
        lock: Arc::clone(&source.paths.lock),
        ..environment(sensor_dir.path())
    };
    append(&source.paths.export, &format!("{EXEC}\n").repeat(EXPORT_LINES))?;
    let audit_log = Arc::new(open_file_log(&sensor_dir.path().join("audit"))?);
    let audit = shared_log_audit(&audit_log);
    let source_settings = SourceSettings {
        max_lines_per_poll: LINES_PER_POLL,
        ..SourceSettings::default()
    };
    let reader = tokio::task::spawn_blocking(move || {
        let outcome = (0..POLLS).try_for_each(|_| poll(&mut source.follower, &source.state, &source.paths, &source_settings, LINE_LIMIT).map(|_| ()));
        (outcome, source)
    });
    let sensor = async {
        let mut supervisor = Supervisor::default();
        for round in 0..TICKS {
            let text = if round % PARITY == 0 {
                show_text("inactive", 0)
            } else {
                show_text("active", 1)
            };
            fs::write(&env.systemctl, text)?;
            supervisor = tick(&env, audit.as_ref(), &settings(0), supervisor, round * TICK_STEP, round * TICK_STEP).await?;
        }
        Ok::<Supervisor, Box<dyn std::error::Error>>(supervisor)
    };
    let (read, ticked) = tokio::join!(reader, sensor);
    let (outcome, finished) = read?;
    outcome?;
    ticked?;
    let spooled = lines(&finished.paths.spool)?;
    let events = spooled.iter().filter(|line| line.contains("agent.sensor")).count();
    assert!(events > 1);
    assert_eq!(spooled.len(), EXPORT_LINES + events);
    spooled
        .iter()
        .try_for_each(|line| serde_json::from_str::<serde_json::Value>(line).map(|_| ()))?;
    Ok(())
}
