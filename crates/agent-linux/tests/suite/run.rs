use crate::support::{append, lines, scoped_logging, setup, EXEC, LEN_TWO, LINE_LIMIT, RELOADED_MILLIS, THREE, TWO};
use crate::types::TestResult;
use agent_channel::types::{PauseFn, PauseFuture};
use agent_linux::app::{run_linux, source_paths};
use agent_linux::cursor::write_cursor;
use agent_linux::error::SourceError;
use agent_linux::model::{Cursor, LinuxFile, Report, SourceSettings, Totals, DEFAULT_POLL_MILLIS};
use agent_linux::run::{run_source, tally};
use arc_swap::ArcSwap;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::process::Command;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;
use tempfile::tempdir;


#[tokio::test]
async fn the_source_polls_and_reads_the_settings_afresh_each_time() -> TestResult {
    let _log = scoped_logging();
    let setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n{EXEC}\n"))?;
    let shared = Arc::new(ArcSwap::from_pointee(SourceSettings::default()));
    let pauses: Arc<Mutex<Vec<Duration>>> = Arc::new(Mutex::new(Vec::new()));
    let seen = Arc::clone(&pauses);
    let swapped = Arc::clone(&shared);
    let pause = move |delay: Duration| -> PauseFuture {
        seen.lock().unwrap_or_else(PoisonError::into_inner).push(delay);
        swapped.store(Arc::new(SourceSettings {
            poll_millis: RELOADED_MILLIS,
            ..SourceSettings::default()
        }));
        Box::pin(async {})
    };
    let totals = run_source(&shared, &setup.paths, LINE_LIMIT, THREE, &pause).await?;
    assert_eq!((totals.polls, totals.spooled, totals.failures), (THREE, TWO, 0));
    let kept = pauses.lock().map_err(|error| error.to_string())?.clone();
    assert_eq!(
        kept,
        vec![
            Duration::from_millis(DEFAULT_POLL_MILLIS),
            Duration::from_millis(RELOADED_MILLIS),
            Duration::from_millis(RELOADED_MILLIS)
        ]
    );
    assert_eq!(lines(&setup.paths.spool)?.len(), LEN_TWO);
    Ok(())
}


#[tokio::test]
async fn a_failing_poll_is_counted_and_the_next_one_runs() -> TestResult {
    let _log = scoped_logging();
    let setup = setup()?;
    let target = setup.dir.path().join("target");
    append(&target, "x\n")?;
    symlink(&target, &setup.paths.export)?;
    let shared = Arc::new(ArcSwap::from_pointee(SourceSettings::default()));
    let totals = run_source(&shared, &setup.paths, LINE_LIMIT, TWO, &|_| Box::pin(async {})).await?;
    assert_eq!((totals.polls, totals.failures, totals.spooled), (TWO, TWO, 0));
    Ok(())
}


#[tokio::test]
async fn a_corrupt_cursor_stops_the_source_at_start() -> TestResult {
    let setup = setup()?;
    fs::write(&setup.paths.cursor_file, "garbage")?;
    let shared = Arc::new(ArcSwap::from_pointee(SourceSettings::default()));
    let outcome = run_source(&shared, &setup.paths, LINE_LIMIT, 1, &|_| Box::pin(async {})).await;
    assert!(matches!(outcome, Err(SourceError::Cursor(_))));
    write_cursor(&setup.state, &setup.paths.cursor_file, Cursor::default())?;
    Ok(())
}


#[test]
fn the_totals_add_up_and_a_missing_file_is_logged_once() -> TestResult {
    let _log = scoped_logging();
    let missing = Report {
        missing: true,
        ..Report::default()
    };
    let first = tally(Totals::default(), Ok(missing));
    assert!(first.waiting);
    let second = tally(first, Ok(missing));
    let found = tally(
        second,
        Ok(Report {
            spooled: TWO,
            malformed: 1,
            unknown: 1,
            oversized: 1,
            rotated: true,
            ..Report::default()
        }),
    );
    assert_eq!(
        (
            found.polls,
            found.spooled,
            found.malformed,
            found.unknown,
            found.oversized,
            found.rotations
        ),
        (THREE, TWO, 1, 1, 1, 1)
    );
    assert!(!found.waiting);
    Ok(())
}


fn write_files(dir: &std::path::Path) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let agent = dir.join("agent.yaml");
    fs::write(
        &agent,
        format!(
            "server: 127.0.0.1:1\nserver_name: server\ncertificate: {root}/absent.pem\nkey: {root}/absent.key\nplatform_ca: {root}/absent-ca.pem\ntenant: t1\nagent_id: a1\nkeys_file: {root}/keys\nstate_file: {root}/state\naudit_file: {root}/agent-audit\nspool_file: {root}/spool\nsequence_file: {root}/sequence\nexecuted_file: {root}/executed\n",
            root = dir.display()
        ),
    )?;
    let config = dir.join("linux.yaml");
    fs::write(
        &config,
        format!(
            "agent_file: {root}/agent.yaml\nexport_path: {root}/export.json\ncursor_file: {root}/cursor\naudit_file: {root}/linux-audit\n",
            root = dir.display()
        ),
    )?;
    Ok(config)
}


#[tokio::test]
async fn the_linux_agent_runs_the_source_and_the_agent_side_by_side() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    append(&dir.path().join("export.json"), &format!("{EXEC}\n{EXEC}\n"))?;
    let totals = run_linux(&config, TWO, &|_| Box::pin(async {})).await?;
    assert_eq!((totals.polls, totals.spooled, totals.agent_runs), (TWO, TWO, 0));
    let spooled = lines(&dir.path().join("spool"))?;
    assert_eq!(spooled.len(), LEN_TWO + 1);
    assert!(spooled.iter().any(|line| line.contains("agent.capabilities")));
    Ok(())
}


#[tokio::test]
async fn the_linux_agent_refuses_missing_files() -> TestResult {
    let dir = tempdir()?;
    assert!(run_linux(&dir.path().join("absent.yaml"), 1, &|_| Box::pin(async {})).await.is_err());
    let config = write_files(dir.path())?;
    fs::remove_file(dir.path().join("agent.yaml"))?;
    assert!(run_linux(&config, 1, &|_| Box::pin(async {})).await.is_err());
    Ok(())
}


#[test]
fn the_source_paths_come_from_the_agent_spool() -> TestResult {
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    let file = core_config::load::load_file::<LinuxFile>(&config)?;
    let agent = agent_channel::agent_app::load_agent_file(&file.agent_file)?;
    let paths = source_paths(&file, &agent);
    assert_eq!(paths.spool, agent.spool_file);
    assert!(paths.sending.to_string_lossy().ends_with("spool.sending"));
    Ok(())
}


#[tokio::test]
async fn a_source_that_fails_at_start_ends_the_agent_at_once() -> TestResult {
    let _log = scoped_logging();
    let dir = tempdir()?;
    let config = write_files(dir.path())?;
    let yielding: &PauseFn = &|_| Box::pin(tokio::task::yield_now());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(WORLD_WRITABLE))?;
    assert!(matches!(run_linux(&config, u64::MAX, yielding).await, Err(SourceError::StateDir(..))));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(PRIVATE))?;
    fs::write(dir.path().join("cursor"), "garbage")?;
    assert!(matches!(run_linux(&config, u64::MAX, yielding).await, Err(SourceError::Cursor(_))));
    fs::remove_file(dir.path().join("cursor"))?;
    assert!(Command::new("mkfifo").arg(dir.path().join("cursor")).status()?.success());
    assert!(matches!(run_linux(&config, u64::MAX, yielding).await, Err(SourceError::NotRegular(_))));
    Ok(())
}


const WORLD_WRITABLE: u32 = 0o777;


const PRIVATE: u32 = 0o700;
