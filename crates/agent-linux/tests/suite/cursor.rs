use crate::types::TestResult;
use agent_linux::cursor::{open_state_dir, read_cursor, state_dir_fault, write_cursor, MAX_CURSOR_BYTES};
use agent_linux::error::{SourceError, StateDirReason};
use agent_linux::model::Cursor;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;


const GROUP_WRITABLE: u32 = 0o770;


const LONG_NAME: usize = 300;


const PRIVATE: u32 = 0o700;


const PROCESS_UID: u32 = 1000;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


const SAMPLE_DEV: u64 = 7;


const SAMPLE_INO: u64 = 9;


const SAMPLE_OFFSET: u64 = 123;


#[test]
fn a_cursor_round_trips_and_a_missing_file_is_the_start() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    let state = open_state_dir(&path)?;
    assert_eq!(read_cursor(&state, &path)?, Cursor::default());
    let cursor = Cursor {
        dev: SAMPLE_DEV,
        ino: SAMPLE_INO,
        offset: SAMPLE_OFFSET,
        skipping: false,
    };
    write_cursor(&state, &path, cursor)?;
    assert_eq!(read_cursor(&state, &path)?, cursor);
    Ok(())
}


#[test]
fn a_malformed_cursor_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    let state = open_state_dir(&path)?;
    ["", "1 2", "1 2 x", "1 2 3 4", "1 2 3 1 5", "1 2 3 x"].iter().try_for_each(|text| {
        fs::write(&path, text)?;
        assert!(matches!(read_cursor(&state, &path), Err(SourceError::Cursor(_))));
        Ok::<(), std::io::Error>(())
    })?;
    Ok(())
}


#[test]
fn a_cursor_that_is_not_a_regular_file_is_refused_at_once() -> TestResult {
    let dir = tempdir()?;
    let state = open_state_dir(&dir.path().join("cursor"))?;
    let sub = dir.path().join("sub");
    fs::create_dir(&sub)?;
    assert!(matches!(read_cursor(&state, &sub), Err(SourceError::NotRegular(_))));
    let fifo = dir.path().join("fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(matches!(read_cursor(&state, &fifo), Err(SourceError::NotRegular(_))));
    let target = dir.path().join("target");
    fs::write(&target, "7 9 123\n")?;
    let link = dir.path().join("link");
    symlink(&target, &link)?;
    assert!(matches!(read_cursor(&state, &link), Err(SourceError::Io(_))));
    Ok(())
}


#[test]
fn an_oversized_or_non_text_cursor_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    let state = open_state_dir(&path)?;
    fs::write(&path, format!("7 9 123 {}", " ".repeat(MAX_CURSOR_BYTES)))?;
    assert!(matches!(read_cursor(&state, &path), Err(SourceError::Cursor(_))));
    fs::write(&path, NOT_UTF8)?;
    assert!(matches!(read_cursor(&state, &path), Err(SourceError::Io(_))));
    fs::write(&path, format!("7 9 123{}", " ".repeat(MAX_CURSOR_BYTES - "7 9 123".len())))?;
    assert!(read_cursor(&state, &path).is_ok());
    Ok(())
}


#[test]
fn the_state_directory_must_belong_to_the_process_or_root_and_not_be_writable() -> TestResult {
    let process_uid = PROCESS_UID;
    let stranger = PROCESS_UID + 1;
    assert_eq!(state_dir_fault(process_uid, process_uid, PRIVATE), None);
    assert_eq!(state_dir_fault(0, process_uid, PRIVATE), None);
    assert_eq!(state_dir_fault(stranger, process_uid, PRIVATE), Some(StateDirReason::WrongOwner));
    assert_eq!(state_dir_fault(process_uid, process_uid, GROUP_WRITABLE), Some(StateDirReason::Writable));
    assert_eq!(state_dir_fault(0, process_uid, GROUP_WRITABLE), Some(StateDirReason::Writable));
    Ok(())
}


#[test]
fn a_cursor_that_cannot_be_written_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let state = open_state_dir(&dir.path().join("cursor"))?;
    let missing = dir.path().join("cursor");
    fs::create_dir(&missing)?;
    fs::create_dir(dir.path().join("cursor.tmp"))?;
    assert!(write_cursor(&state, &missing, Cursor::default()).is_err());
    assert!(matches!(
        write_cursor(&state, Path::new("/"), Cursor::default()),
        Err(SourceError::Cursor(_))
    ));
    assert!(matches!(read_cursor(&state, Path::new("/")), Err(SourceError::Cursor(_))));
    Ok(())
}


#[test]
fn the_skipping_flag_round_trips_and_a_legacy_cursor_reads_as_not_skipping() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    let state = open_state_dir(&path)?;
    let cursor = Cursor {
        dev: SAMPLE_DEV,
        ino: SAMPLE_INO,
        offset: SAMPLE_OFFSET,
        skipping: true,
    };
    write_cursor(&state, &path, cursor)?;
    assert_eq!(read_cursor(&state, &path)?, cursor);
    fs::write(&path, "7 9 123\n")?;
    assert!(!read_cursor(&state, &path)?.skipping);
    Ok(())
}


#[test]
fn a_planted_symlink_or_stale_file_is_never_followed() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    let state = open_state_dir(&path)?;
    let victim = dir.path().join("victim");
    fs::write(&victim, "keep")?;
    symlink(&victim, dir.path().join("cursor.tmp"))?;
    write_cursor(&state, &path, Cursor::default())?;
    assert_eq!(fs::read_to_string(&victim)?, "keep");
    fs::write(dir.path().join("cursor.tmp"), "stale")?;
    write_cursor(&state, &path, Cursor::default())?;
    assert!(read_cursor(&state, &path).is_ok());
    fs::create_dir(dir.path().join("cursor.tmp"))?;
    assert!(write_cursor(&state, &path, Cursor::default()).is_err());
    Ok(())
}


fn reason_of(path: &Path) -> Result<StateDirReason, Box<dyn std::error::Error>> {
    match open_state_dir(path) {
        Err(SourceError::StateDir(_, reason)) => Ok(reason),
        other => Err(format!("expected a StateDir refusal, got {other:?}").into()),
    }
}


#[test]
fn each_state_directory_refusal_names_its_reason() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("cursor");
    assert!(open_state_dir(&path).is_ok());
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(GROUP_WRITABLE))?;
    assert_eq!(reason_of(&path)?, StateDirReason::Writable);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(PRIVATE))?;
    assert_eq!(reason_of(Path::new("/"))?, StateDirReason::NoDirectory);
    assert_eq!(reason_of(&dir.path().join("absent").join("cursor"))?, StateDirReason::Missing);
    fs::write(dir.path().join("plain"), "x")?;
    assert_eq!(reason_of(&dir.path().join("plain").join("cursor"))?, StateDirReason::NotDirectory);
    symlink(dir.path(), dir.path().join("link"))?;
    assert_eq!(reason_of(&dir.path().join("link").join("cursor"))?, StateDirReason::NotDirectory);
    assert!(open_state_dir(Path::new("cursor")).is_ok());
    assert!(matches!(
        open_state_dir(&Path::new(&"x".repeat(LONG_NAME)).join("cursor")),
        Err(SourceError::Io(_))
    ));
    let texts = [
        StateDirReason::Writable,
        StateDirReason::Missing,
        StateDirReason::NotDirectory,
        StateDirReason::WrongOwner,
        StateDirReason::NoDirectory,
    ]
    .map(|reason| reason.to_string());
    assert_eq!(texts.iter().collect::<std::collections::HashSet<_>>().len(), texts.len());
    Ok(())
}


#[test]
fn a_swapped_state_path_does_not_redirect_the_cursor_write() -> TestResult {
    let dir = tempdir()?;
    let state_path = dir.path().join("state");
    fs::create_dir(&state_path)?;
    let cursor_file = state_path.join("cursor");
    let state = open_state_dir(&cursor_file)?;
    let moved = dir.path().join("moved");
    fs::rename(&state_path, &moved)?;
    let attacker = dir.path().join("attacker");
    fs::create_dir(&attacker)?;
    symlink(&attacker, &state_path)?;
    let cursor = Cursor {
        dev: SAMPLE_DEV,
        ino: SAMPLE_INO,
        offset: SAMPLE_OFFSET,
        skipping: false,
    };
    write_cursor(&state, &cursor_file, cursor)?;
    assert_eq!(fs::read_dir(&attacker)?.count(), 0);
    assert_eq!(read_cursor(&state, &cursor_file)?, cursor);
    assert!(moved.join("cursor").is_file());
    Ok(())
}
