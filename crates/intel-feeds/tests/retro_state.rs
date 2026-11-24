#[path = "common/types.rs"]
mod types;


use intel_feeds::limits::MAX_STATE_BYTES;
use intel_feeds::retro_state::{read_end, start_of, write_end, StateError, NO_PREVIOUS_RUN, RESUMED, STATE_UNREADABLE};
use std::fs;
use std::io::ErrorKind;
use tempfile::tempdir;
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const END: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const END_SECONDS: &str = "1793707200";


const BEFORE_EPOCH: OffsetDateTime = datetime!(1969-12-31 23:59:59 UTC);


const ONE_MEGABYTE: usize = 1_048_576;


#[test]
fn an_end_is_written_as_digits_and_read_back() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("retro.state");
    write_end(&path, END)?;
    assert_eq!(fs::read_to_string(&path)?, END_SECONDS);
    assert_eq!(read_end(&path)?, Some(END));
    assert!(!dir.path().join("retro.tmp").exists());
    Ok(())
}


#[test]
fn a_missing_file_is_none_and_anything_else_is_named() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("retro.state");
    assert!(read_end(&path)?.is_none());
    fs::write(&path, "")?;
    assert!(matches!(read_end(&path), Err(StateError::NotDigits)));
    fs::write(&path, "17937072ab")?;
    assert!(matches!(read_end(&path), Err(StateError::NotDigits)));
    fs::write(&path, "1793707200\n")?;
    assert!(matches!(read_end(&path), Err(StateError::NotDigits)));
    fs::write(&path, "-1")?;
    assert!(matches!(read_end(&path), Err(StateError::NotDigits)));
    fs::write(&path, "99999999999999999999")?;
    assert!(matches!(read_end(&path), Err(StateError::Range)));
    fs::write(&path, "9223372036854775807")?;
    assert!(matches!(read_end(&path), Err(StateError::Range)));
    fs::write(&path, "0")?;
    assert_eq!(read_end(&path)?, Some(OffsetDateTime::UNIX_EPOCH));
    fs::write(&path, "1".repeat(MAX_STATE_BYTES as usize + 1))?;
    assert!(matches!(read_end(&path), Err(StateError::Read(_))));
    fs::write(&path, "1".repeat(ONE_MEGABYTE))?;
    assert!(matches!(read_end(&path), Err(StateError::Read(_))));
    assert!(matches!(read_end(&path.join("inner")), Err(StateError::Read(_))));
    fs::remove_file(&path)?;
    fs::create_dir(&path)?;
    assert!(matches!(read_end(&path), Err(StateError::Read(_))));
    Ok(())
}


#[test]
fn a_failed_write_is_an_error_and_leaves_the_old_file() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("retro.state");
    write_end(&path, END)?;
    assert_eq!(
        write_end(&path, BEFORE_EPOCH).err().map(|error| error.kind()),
        Some(ErrorKind::InvalidInput)
    );
    assert_eq!(fs::read_to_string(&path)?, END_SECONDS);
    let missing = dir.path().join("absent").join("retro.state");
    assert!(write_end(&missing, END).is_err());
    let target = dir.path().join("directory");
    fs::create_dir(&target)?;
    assert!(write_end(&target, END).is_err());
    Ok(())
}


#[test]
fn the_start_names_what_the_first_round_starts_from() -> TestResult {
    assert_eq!(start_of(Ok(Some(END))), (Some(END), RESUMED));
    assert_eq!(start_of(Ok(None)), (None, NO_PREVIOUS_RUN));
    assert_eq!(start_of(Err(StateError::NotDigits)), (None, STATE_UNREADABLE));
    Ok(())
}
