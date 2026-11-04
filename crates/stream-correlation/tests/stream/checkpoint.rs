use crate::support::{bench, failed_login, feed, restart, FailingWriter, FlushFails, BRUTE_FORCE, LOGIN, SEC_2};
use crate::types::TestResult;
use std::fs;
use std::fs::File;
use std::io;
use std::path::Path;
use stream_correlation::checkpoint::{load_checkpoint, save_checkpoint, save_checkpoint_with, write_checkpoint, CHECKPOINT_VERSION};
use stream_correlation::engine::snapshot;
use stream_correlation::error::CorrelationError;
use stream_correlation::window::State;


const HALF: usize = 2;


fn restart_error(bench: &crate::support::Bench) -> Result<CorrelationError, Box<dyn std::error::Error>> {
    match restart(bench) {
        Ok(_) => Err("the engine started".into()),
        Err(error) => Ok(error),
    }
}


#[test]
fn checkpoint_round_trips() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    feed(&bench.engine, &failed_login(0, "a", "h1"));
    feed(&bench.engine, &failed_login(1, "b", "h1"));
    let state = snapshot(&bench.engine);
    save_checkpoint(&bench.checkpoint, &state)?;
    assert_eq!(load_checkpoint(&bench.checkpoint)?, Some(state));
    assert!(!bench.checkpoint.with_extension("tmp").exists());
    Ok(())
}


#[test]
fn a_window_spanning_a_restart_still_fires() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    feed(&bench.engine, &failed_login(0, "a", "h1"));
    feed(&bench.engine, &failed_login(1, "b", "h1"));
    save_checkpoint(&bench.checkpoint, &snapshot(&bench.engine))?;
    let revived = restart(&bench)?;
    let alerts = feed(&revived, &failed_login(SEC_2, "c", "h1"));
    assert_eq!(
        alerts.first().map(|alert| alert.event_ids.clone()),
        Some(vec!["a".to_string(), "b".to_string(), "c".to_string()])
    );
    Ok(())
}


#[test]
fn a_missing_checkpoint_is_a_first_start() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    assert_eq!(load_checkpoint(&bench.checkpoint)?, None);
    assert_eq!(snapshot(&bench.engine), State::default());
    Ok(())
}


#[test]
fn a_corrupt_checkpoint_is_refused() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    fs::write(&bench.checkpoint, "not json at all")?;
    assert!(matches!(restart_error(&bench)?, CorrelationError::CorruptCheckpoint { .. }));
    save_checkpoint(&bench.checkpoint, &State::default())?;
    let text = fs::read_to_string(&bench.checkpoint)?;
    fs::write(&bench.checkpoint, text.get(..text.len() / HALF).ok_or("short text")?)?;
    assert!(matches!(restart_error(&bench)?, CorrelationError::CorruptCheckpoint { .. }));
    fs::write(&bench.checkpoint, "")?;
    assert!(matches!(restart_error(&bench)?, CorrelationError::CorruptCheckpoint { .. }));
    Ok(())
}


#[test]
fn another_version_is_refused() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    let other = CHECKPOINT_VERSION + 1;
    fs::write(&bench.checkpoint, format!("{{\"version\":{other},\"state\":{{\"watermark_ms\":null,\"counters\":{{\"processed\":0,\"invalid\":0,\"late\":0,\"dropped_events\":0,\"dropped_groups\":0,\"alerts\":0}},\"rules\":{{}}}}}}"))?;
    assert!(matches!(restart_error(&bench)?, CorrelationError::CheckpointVersion { found, .. } if found == other));
    Ok(())
}


#[test]
fn unreadable_and_unwritable_paths_are_typed_errors() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    let directory = bench.dir.path().join("a-directory");
    fs::create_dir(&directory)?;
    assert!(matches!(load_checkpoint(&directory), Err(CorrelationError::CheckpointIo { .. })));
    assert!(matches!(
        save_checkpoint(&directory, &State::default()),
        Err(CorrelationError::CheckpointIo { .. })
    ));
    let missing = bench.dir.path().join("no-such-dir").join("checkpoint.json");
    assert!(matches!(
        save_checkpoint(&missing, &State::default()),
        Err(CorrelationError::CheckpointIo { .. })
    ));
    Ok(())
}


#[test]
fn write_failures_are_reported() -> TestResult {
    assert!(matches!(
        write_checkpoint(&mut FailingWriter, &State::default()),
        Err(CorrelationError::Serialize(_))
    ));
    assert!(matches!(
        write_checkpoint(&mut FlushFails, &State::default()),
        Err(CorrelationError::Output(_))
    ));
    Ok(())
}


fn refuse_sync(_file: &File) -> io::Result<()> {
    Err(io::Error::other("sync refused"))
}


#[test]
fn a_failed_sync_or_write_leaves_the_old_checkpoint() -> TestResult {
    let bench = bench(&[LOGIN, BRUTE_FORCE])?;
    save_checkpoint(&bench.checkpoint, &State::default())?;
    let before = fs::read_to_string(&bench.checkpoint)?;
    let temporary = bench.checkpoint.with_extension("tmp");
    let mut state = State::default();
    state.counters.processed = 1;
    assert!(matches!(
        save_checkpoint_with(&temporary, &bench.checkpoint, &state, refuse_sync),
        Err(CorrelationError::CheckpointIo { .. })
    ));
    assert!(matches!(
        save_checkpoint_with(Path::new("/dev/full"), &bench.checkpoint, &state, File::sync_all),
        Err(CorrelationError::Serialize(_))
    ));
    assert_eq!(fs::read_to_string(&bench.checkpoint)?, before);
    Ok(())
}
