use crate::types::TestResult;
use agent_linux::cursor::{read_cursor, write_cursor};
use agent_linux::error::SourceError;
use agent_linux::model::Cursor;
use std::fs;
use tempfile::tempdir;


const SAMPLE_DEV: u64 = 7;


const SAMPLE_INO: u64 = 9;


const SAMPLE_OFFSET: u64 = 123;


#[test]
fn a_cursor_round_trips_and_a_missing_file_is_the_start() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    assert_eq!(read_cursor(&path)?, Cursor::default());
    let cursor = Cursor {
        dev: SAMPLE_DEV,
        ino: SAMPLE_INO,
        offset: SAMPLE_OFFSET,
    };
    write_cursor(&path, cursor)?;
    assert_eq!(read_cursor(&path)?, cursor);
    Ok(())
}


#[test]
fn a_malformed_cursor_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    ["", "1 2", "1 2 x", "1 2 3 4"].iter().try_for_each(|text| {
        fs::write(&path, text)?;
        assert!(matches!(read_cursor(&path), Err(SourceError::Cursor(_))));
        Ok::<(), std::io::Error>(())
    })?;
    Ok(())
}


#[test]
fn an_unreadable_cursor_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    assert!(matches!(read_cursor(dir.path()), Err(SourceError::Io(_))));
    Ok(())
}


#[test]
fn a_cursor_that_cannot_be_written_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let missing = dir.path().join("absent").join("cursor");
    assert!(write_cursor(&missing, Cursor::default()).is_err());
    Ok(())
}
