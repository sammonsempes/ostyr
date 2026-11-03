use crate::common::types::TestResult;
use crate::common::{command, engine_at, replace_file, routine_envelope, sensitive_envelope, setup, verifier_with, NOW, SECOND};
use agent_command::error::{CommandError, StoreError};
use agent_command::model::{Action, Sequences, MAX_SEQUENCE_ADVANCE};
use agent_command::store::{file_saver, load_sequences, save_sequences};
use agent_command::verify::{open_verifier, open_verifier_with, verify_command};
use std::fs;
use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tempfile::tempdir;


const STORED: u64 = 7;


fn both(sequence: u64) -> Sequences {
    Sequences {
        routine: sequence,
        sensitive: sequence,
    }
}


#[test]
fn a_missing_file_is_a_fresh_agent() -> TestResult {
    let dir = tempdir()?;
    assert_eq!(load_sequences(&dir.path().join("sequence"))?, Sequences::default());
    Ok(())
}


#[test]
fn a_saved_sequence_is_loaded_back() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("sequence");
    let split = Sequences {
        routine: STORED,
        sensitive: STORED + 1,
    };
    save_sequences(&path, &split)?;
    assert_eq!(load_sequences(&path)?, split);
    save_sequences(&path, &both(STORED + 1))?;
    assert_eq!(load_sequences(&path)?, both(STORED + 1));
    assert_eq!(fs::read_dir(dir.path())?.count(), 1, "no staging file is left behind");
    Ok(())
}


#[test]
fn a_corrupt_or_unreadable_store_is_an_error_never_zero() -> TestResult {
    let dir = tempdir()?;
    let corrupt = dir.path().join("corrupt");
    fs::write(&corrupt, "garbage")?;
    assert!(matches!(load_sequences(&corrupt), Err(StoreError::Corrupt { .. })));
    assert!(matches!(load_sequences(dir.path()), Err(StoreError::Io { .. })));
    fs::write(&corrupt, "routine x sensitive 1")?;
    assert!(matches!(load_sequences(&corrupt), Err(StoreError::Corrupt { .. })));
    fs::write(&corrupt, "routine 1 sensitive y")?;
    assert!(matches!(load_sequences(&corrupt), Err(StoreError::Corrupt { .. })));
    fs::write(&corrupt, "1 2")?;
    assert!(matches!(load_sequences(&corrupt), Err(StoreError::Layout { .. })));
    fs::write(&corrupt, "")?;
    assert!(matches!(load_sequences(&corrupt), Err(StoreError::Layout { .. })));
    Ok(())
}


#[test]
fn saving_fails_for_a_missing_directory_and_for_a_directory_target() -> TestResult {
    let dir = tempdir()?;
    assert!(save_sequences(&dir.path().join("missing").join("sequence"), &both(1)).is_err());
    assert!(save_sequences(dir.path(), &both(1)).is_err());
    assert!(file_saver(dir.path().join("missing").join("sequence"))(&both(1)).is_err());
    Ok(())
}


#[test]
fn the_sequence_survives_reopening_the_store() -> TestResult {
    let setup = setup()?;
    let state = setup.keys_path.with_file_name("sequence");
    let first = open_verifier(crate::common::AGENT, crate::common::TENANT, Arc::clone(&setup.engine), &state)?;
    let bytes = routine_envelope(&command(STORED, Action::Ping))?;
    assert!(verify_command(&first, &bytes, NOW).is_ok());
    assert_eq!(
        load_sequences(&state)?,
        Sequences {
            routine: STORED,
            sensitive: 0
        }
    );
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
        Sequences::default(),
        Box::new(move |_sequences| {
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


#[test]
fn an_old_single_sequence_file_is_read_as_both_classes() -> TestResult {
    let setup = setup()?;
    let state = setup.keys_path.with_file_name("sequence");
    replace_file(&state, "7\n")?;
    assert_eq!(load_sequences(&state)?, both(STORED));
    let verifier = open_verifier(crate::common::AGENT, crate::common::TENANT, Arc::clone(&setup.engine), &state)?;
    let replay = routine_envelope(&command(STORED, Action::Ping))?;
    assert!(matches!(verify_command(&verifier, &replay, NOW), Err(CommandError::ReplayedSequence)));
    let replay_sensitive = sensitive_envelope(&command(STORED, Action::Isolate))?;
    assert!(matches!(
        verify_command(&verifier, &replay_sensitive, NOW),
        Err(CommandError::ReplayedSequence)
    ));
    Ok(())
}


#[test]
fn the_classes_have_independent_sequences_on_disk() -> TestResult {
    let setup = setup()?;
    let state = setup.keys_path.with_file_name("sequence");
    let verifier = open_verifier(crate::common::AGENT, crate::common::TENANT, Arc::clone(&setup.engine), &state)?;
    assert!(verify_command(&verifier, &routine_envelope(&command(STORED, Action::Ping))?, NOW).is_ok());
    assert!(verify_command(&verifier, &sensitive_envelope(&command(1, Action::Isolate))?, NOW).is_ok());
    assert_eq!(
        load_sequences(&state)?,
        Sequences {
            routine: STORED,
            sensitive: 1
        }
    );
    assert!(verify_command(&verifier, &sensitive_envelope(&command(SECOND, Action::Isolate))?, NOW).is_ok());
    assert_eq!(
        load_sequences(&state)?,
        Sequences {
            routine: STORED,
            sensitive: SECOND
        }
    );
    Ok(())
}


#[test]
fn a_jump_over_the_cap_is_refused_without_advancing_anything() -> TestResult {
    let setup = setup()?;
    let state = setup.keys_path.with_file_name("sequence");
    let verifier = open_verifier(crate::common::AGENT, crate::common::TENANT, Arc::clone(&setup.engine), &state)?;
    let jumps = [u64::MAX, MAX_SEQUENCE_ADVANCE + 1];
    jumps.iter().try_for_each(|jump| -> TestResult {
        let refusal = verify_command(&verifier, &routine_envelope(&command(*jump, Action::Ping))?, NOW);
        assert!(matches!(refusal, Err(CommandError::SequenceJump)));
        Ok(())
    })?;
    assert_eq!(load_sequences(&state)?, Sequences::default());
    assert!(verify_command(&verifier, &sensitive_envelope(&command(1, Action::Isolate))?, NOW).is_ok());
    assert!(verify_command(&verifier, &routine_envelope(&command(MAX_SEQUENCE_ADVANCE, Action::Ping))?, NOW).is_ok());
    assert_eq!(
        load_sequences(&state)?,
        Sequences {
            routine: MAX_SEQUENCE_ADVANCE,
            sensitive: 1
        }
    );
    Ok(())
}
