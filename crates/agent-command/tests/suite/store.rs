use crate::common::types::TestResult;
use crate::common::{command, engine_at, replace_file, routine_envelope, setup, verifier_with, NOW};
use agent_command::error::{CommandError, StoreError};
use agent_command::model::Action;
use agent_command::store::{file_saver, load_sequence, save_sequence, sync_directory};
use agent_command::verify::{open_verifier, open_verifier_with, verify_command};
use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tempfile::tempdir;


const STORED: u64 = 7;


#[test]
fn a_missing_file_is_a_fresh_agent() -> TestResult {
    let dir = tempdir()?;
    assert_eq!(load_sequence(&dir.path().join("sequence"))?, 0);
    Ok(())
}


#[test]
fn a_saved_sequence_is_loaded_back() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("sequence");
    save_sequence(&path, STORED)?;
    assert_eq!(load_sequence(&path)?, STORED);
    save_sequence(&path, STORED + 1)?;
    assert_eq!(load_sequence(&path)?, STORED + 1);
    assert_eq!(fs::read_dir(dir.path())?.count(), 1, "no staging file is left behind");
    Ok(())
}


#[test]
fn a_corrupt_or_unreadable_store_is_an_error_never_zero() -> TestResult {
    let dir = tempdir()?;
    let corrupt = dir.path().join("corrupt");
    fs::write(&corrupt, "not a number")?;
    assert!(matches!(load_sequence(&corrupt), Err(StoreError::Corrupt { .. })));
    assert!(matches!(load_sequence(dir.path()), Err(StoreError::Io { .. })));
    Ok(())
}


#[test]
fn saving_fails_for_a_missing_directory_and_for_a_directory_target() -> TestResult {
    let dir = tempdir()?;
    assert!(save_sequence(&dir.path().join("missing").join("sequence"), 1).is_err());
    assert!(save_sequence(dir.path(), 1).is_err());
    assert!(sync_directory(&dir.path().join("missing")).is_err());
    assert!(file_saver(dir.path().join("missing").join("sequence"))(1).is_err());
    Ok(())
}


#[test]
fn the_sequence_survives_reopening_the_store() -> TestResult {
    let setup = setup()?;
    let state = setup.keys_path.with_file_name("sequence");
    let first = open_verifier(crate::common::AGENT, crate::common::TENANT, Arc::clone(&setup.engine), &state)?;
    let bytes = routine_envelope(&command(STORED, Action::Ping))?;
    assert!(verify_command(&first, &bytes, NOW).is_ok());
    assert_eq!(load_sequence(&state)?, STORED);
    let reopened = open_verifier(crate::common::AGENT, crate::common::TENANT, Arc::clone(&setup.engine), &state)?;
    assert!(matches!(verify_command(&reopened, &bytes, NOW), Err(CommandError::ReplayedSequence)));
    let next = routine_envelope(&command(STORED + 1, Action::Ping))?;
    assert!(verify_command(&reopened, &next, NOW).is_ok());
    Ok(())
}


#[test]
fn opening_with_a_corrupt_store_fails() -> TestResult {
    let setup = setup()?;
    let state = setup.keys_path.with_file_name("sequence");
    replace_file(&state, "garbage")?;
    let opened = open_verifier(crate::common::AGENT, crate::common::TENANT, Arc::clone(&setup.engine), &state);
    assert!(matches!(opened, Err(StoreError::Corrupt { .. })));
    Ok(())
}


#[test]
fn a_failing_store_refuses_the_command_and_does_not_advance() -> TestResult {
    let setup = setup()?;
    let failing = Arc::new(AtomicBool::new(true));
    let switch = Arc::clone(&failing);
    let verifier = open_verifier_with(
        crate::common::AGENT,
        crate::common::TENANT,
        Arc::clone(&setup.engine),
        0,
        Box::new(move |_sequence| {
            if switch.load(Ordering::SeqCst) {
                Err(io::Error::other("disk full"))
            } else {
                Ok(())
            }
        }),
    );
    let bytes = routine_envelope(&command(1, Action::Ping))?;
    assert!(matches!(verify_command(&verifier, &bytes, NOW), Err(CommandError::Store(_))));
    failing.store(false, Ordering::SeqCst);
    assert!(verify_command(&verifier, &bytes, NOW).is_ok());
    Ok(())
}


#[test]
fn the_engine_helper_and_the_verifier_helper_agree() -> TestResult {
    let setup = setup()?;
    let engine = engine_at(&setup.keys_path)?;
    let verifier = verifier_with(engine, 0);
    assert!(verify_command(&verifier, &routine_envelope(&command(1, Action::Ping))?, NOW).is_ok());
    Ok(())
}
