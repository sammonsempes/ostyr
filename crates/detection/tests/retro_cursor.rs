#![cfg(unix)]

#[path = "retro_cursor/types.rs"]
mod types;


use detection::error::CursorError;
use detection::retro_cursor::{
    find_entry, load_cursors, prune_cursors, save_cursors, save_cursors_with, upsert_entry, write_cursors, CursorEntry, RetroCursors, CURSOR_VERSION,
    MAX_CURSOR_BYTES,
};
use std::fs::{self, File};
use std::io::{self, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use tempfile::tempdir;
use types::TestResult;


const NEXT: i64 = 1_793_664_000;


const STEP: i64 = 600;


const FULL_DEVICE: &str = "/dev/full";


const OTHERS_AND_GROUP_BITS: u32 = 0o077;


fn entry(tenant: &str, fingerprint: &str, next: i64) -> CursorEntry {
    CursorEntry {
        tenant: tenant.to_owned(),
        fingerprint: fingerprint.to_owned(),
        next,
        step: STEP,
    }
}


fn sample() -> RetroCursors {
    RetroCursors {
        entries: vec![entry("t-one", "aa", NEXT), entry("t-two", "bb", NEXT + 1)],
    }
}


fn sync_ok(_file: &File) -> io::Result<()> {
    Ok(())
}


fn sync_fails(_file: &File) -> io::Result<()> {
    Err(io::Error::other("sync"))
}


fn rename_ok(from: &Path, to: &Path) -> io::Result<()> {
    fs::rename(from, to)
}


fn rename_fails(_from: &Path, _to: &Path) -> io::Result<()> {
    Err(io::Error::other("rename"))
}


fn dir_ok(_path: &Path) -> io::Result<()> {
    Ok(())
}


fn dir_fails(_path: &Path) -> io::Result<()> {
    Err(io::Error::other("directory"))
}


struct FailingWrite {
    fail_flush: bool,
}


impl Write for FailingWrite {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if self.fail_flush {
            Ok(buffer.len())
        } else {
            Err(io::Error::other("write"))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush"))
    }
}


#[test]
fn an_entry_is_found_by_tenant_and_fingerprint_and_replaced_in_place() -> TestResult {
    let cursors = sample();
    assert_eq!(find_entry(&cursors, "t-one", "aa").map(|found| found.next), Some(NEXT));
    assert!(find_entry(&cursors, "t-one", "bb").is_none());
    assert!(find_entry(&cursors, "t-two", "aa").is_none());
    let moved = upsert_entry(&cursors, entry("t-one", "aa", NEXT + STEP));
    assert_eq!(moved.entries.len(), cursors.entries.len());
    assert_eq!(find_entry(&moved, "t-one", "aa").map(|found| found.next), Some(NEXT + STEP));
    let added = upsert_entry(&cursors, entry("t-a", "zz", NEXT));
    assert_eq!(added.entries.first().map(|found| found.tenant.as_str()), Some("t-a"));
    Ok(())
}


#[test]
fn pruning_keeps_only_the_live_tenant_and_rule_pairs() -> TestResult {
    let live = vec![("t-one".to_owned(), "aa".to_owned()), ("t-two".to_owned(), "zz".to_owned())];
    let pruned = prune_cursors(&sample(), &live);
    assert_eq!(pruned.entries, vec![entry("t-one", "aa", NEXT)]);
    Ok(())
}


#[test]
fn a_saved_document_loads_back_and_a_missing_file_is_no_cursor_yet() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("retro-cursors.json");
    assert_eq!(load_cursors(&path)?, RetroCursors::default());
    save_cursors(&path, &sample())?;
    assert_eq!(load_cursors(&path)?, sample());
    assert!(!directory.path().join("retro-cursors.json.new").exists());
    assert_eq!(fs::metadata(&path)?.permissions().mode() & OTHERS_AND_GROUP_BITS, 0);
    Ok(())
}


#[test]
fn a_file_that_cannot_be_trusted_is_an_error_never_an_empty_state() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("c.json");
    fs::write(&path, "{")?;
    assert!(matches!(load_cursors(&path), Err(CursorError::Corrupt)));
    fs::write(&path, r#"{"version":1,"cursors":{"entries":[],"extra":1}}"#)?;
    assert!(matches!(load_cursors(&path), Err(CursorError::Corrupt)));
    fs::write(&path, format!(r#"{{"version":{},"cursors":{{"entries":[]}}}}"#, CURSOR_VERSION + 1))?;
    assert!(matches!(load_cursors(&path), Err(CursorError::Version(found)) if found == CURSOR_VERSION + 1));
    fs::write(
        &path,
        r#"{"version":1,"cursors":{"entries":[{"tenant":"t","fingerprint":"f","next":-1,"step":60}]}}"#,
    )?;
    assert!(matches!(load_cursors(&path), Err(CursorError::Range)));
    fs::write(
        &path,
        r#"{"version":1,"cursors":{"entries":[{"tenant":"t","fingerprint":"f","next":4294967296,"step":60}]}}"#,
    )?;
    assert!(matches!(load_cursors(&path), Err(CursorError::Range)));
    let big = File::create(&path)?;
    big.set_len(MAX_CURSOR_BYTES + 1)?;
    assert!(matches!(load_cursors(&path), Err(CursorError::TooLarge(MAX_CURSOR_BYTES))));
    assert!(matches!(load_cursors(directory.path()), Err(CursorError::Read(_))));
    assert!(matches!(load_cursors(&path.join("child")), Err(CursorError::Read(_))));
    Ok(())
}


#[test]
fn every_failed_save_step_is_an_error_and_keeps_the_old_file() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("c.json");
    save_cursors(&path, &sample())?;
    let newer = upsert_entry(&sample(), entry("t-one", "aa", NEXT + STEP));
    assert!(matches!(
        save_cursors_with(&path, &newer, sync_fails, rename_ok, dir_ok),
        Err(CursorError::Write(_))
    ));
    assert!(matches!(
        save_cursors_with(&path, &newer, sync_ok, rename_fails, dir_ok),
        Err(CursorError::Write(_))
    ));
    assert_eq!(load_cursors(&path)?, sample());
    assert!(matches!(
        save_cursors_with(&path, &newer, sync_ok, rename_ok, dir_fails),
        Err(CursorError::Write(_))
    ));
    assert_eq!(load_cursors(&path)?, newer);
    let full = directory.path().join("full.json");
    symlink(FULL_DEVICE, directory.path().join("full.json.new"))?;
    assert!(matches!(save_cursors(&full, &sample()), Err(CursorError::Write(_))));
    let missing = directory.path().join("absent").join("c.json");
    assert!(matches!(save_cursors(&missing, &sample()), Err(CursorError::Write(_))));
    Ok(())
}


#[test]
fn a_failing_writer_is_a_write_error_at_the_write_or_the_flush() -> TestResult {
    assert!(matches!(
        write_cursors(&mut FailingWrite { fail_flush: false }, &sample()),
        Err(CursorError::Write(_))
    ));
    assert!(matches!(
        write_cursors(&mut FailingWrite { fail_flush: true }, &sample()),
        Err(CursorError::Write(_))
    ));
    Ok(())
}
