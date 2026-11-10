use crate::types::TestResult;
use agent_linux::cursor::{check_state_dir, read_cursor, write_cursor};
use agent_linux::error::SourceError;
use agent_linux::model::Cursor;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use tempfile::tempdir;


const GROUP_WRITABLE: u32 = 0o770;


const PRIVATE: u32 = 0o700;


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
        skipping: false,
    };
    write_cursor(&path, cursor)?;
    assert_eq!(read_cursor(&path)?, cursor);
    Ok(())
}


#[test]
fn a_malformed_cursor_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    ["", "1 2", "1 2 x", "1 2 3 4", "1 2 3 1 5", "1 2 3 x"].iter().try_for_each(|text| {
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


#[test]
fn the_skipping_flag_round_trips_and_a_legacy_cursor_reads_as_not_skipping() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    let cursor = Cursor {
        dev: SAMPLE_DEV,
        ino: SAMPLE_INO,
        offset: SAMPLE_OFFSET,
        skipping: true,
    };
    write_cursor(&path, cursor)?;
    assert_eq!(read_cursor(&path)?, cursor);
    fs::write(&path, "7 9 123\n")?;
    assert!(!read_cursor(&path)?.skipping);
    Ok(())
}


#[test]
fn a_planted_symlink_or_stale_file_is_never_followed() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    let victim = dir.path().join("victim");
    fs::write(&victim, "keep")?;
    symlink(&victim, dir.path().join("cursor.tmp"))?;
    write_cursor(&path, Cursor::default())?;
    assert_eq!(fs::read_to_string(&victim)?, "keep");
    fs::write(dir.path().join("cursor.tmp"), "stale")?;
    write_cursor(&path, Cursor::default())?;
    assert!(read_cursor(&path).is_ok());
    fs::create_dir(dir.path().join("cursor.tmp"))?;
    assert!(write_cursor(&path, Cursor::default()).is_err());
    Ok(())
}


#[test]
fn a_group_or_world_writable_state_directory_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    assert!(check_state_dir(&path).is_ok());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert!(matches!(check_state_dir(&path), Err(SourceError::StateDir(_))));
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(PRIVATE))?;
    assert!(matches!(check_state_dir(Path::new("/")), Err(SourceError::StateDir(_))));
    assert!(matches!(
        check_state_dir(&dir.path().join("absent").join("cursor")),
        Err(SourceError::Io(_))
    ));
    Ok(())
}
