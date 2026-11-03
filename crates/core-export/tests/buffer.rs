#[path = "common/types.rs"]
mod types;


use core_export::buffer::{
    batches_size, buffered_bytes, create_file, drain, enqueue, list_batches, next_counter, sync_path, write_batch, Enqueued, NAME_WIDTH,
};
use core_export::error::ExportError;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use tempfile::tempdir;
use types::TestResult;


const MAX_BYTES: u64 = 1024;


const NEXT_AFTER_SEVEN: u64 = 8;


const SMALL_BATCH_BYTES: u64 = 3;


const BIG_BATCH_BYTES: u64 = 4;


const TIGHT_LIMIT: u64 = 6;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const BATCHES_BUFFERED: usize = 2;


const FSYNC_CALLS: u32 = 2;


fn stored_path(outcome: Enqueued) -> Result<PathBuf, &'static str> {
    match outcome {
        Enqueued::Stored(path) => Ok(path),
        Enqueued::Saturated => Err("saturated"),
    }
}


#[test]
fn a_missing_directory_is_an_empty_buffer() -> TestResult {
    let dir = tempdir()?;
    let missing = dir.path().join("absent");
    assert!(list_batches(&missing)?.is_empty());
    assert_eq!(buffered_bytes(&missing)?, u64::MIN);
    assert_eq!(batches_size(&[])?, u64::MIN);
    assert_eq!(drain(&missing, &mut |_body| Ok(()))?, usize::MIN);
    Ok(())
}


#[test]
fn batches_are_stored_in_order_and_ignore_temporary_files() -> TestResult {
    let dir = tempdir()?;
    let buffer = dir.path().join("buffer");
    let first = stored_path(enqueue(&buffer, "[1]", MAX_BYTES, &mut create_file, &mut sync_path)?)?;
    let second = stored_path(enqueue(&buffer, "[22]", MAX_BYTES, &mut create_file, &mut sync_path)?)?;
    fs::write(buffer.join("partial.tmp"), "[3")?;
    assert_eq!(list_batches(&buffer)?, vec![first.clone(), second]);
    assert_eq!(first.file_stem().and_then(|stem| stem.to_str()).map(str::len), Some(NAME_WIDTH));
    assert_eq!(buffered_bytes(&buffer)?, SMALL_BATCH_BYTES + BIG_BATCH_BYTES);
    Ok(())
}


#[test]
fn the_counter_continues_after_the_highest_name() -> TestResult {
    assert_eq!(next_counter(&[]), u64::MIN);
    let batches = vec![
        PathBuf::from("0003.batch"),
        PathBuf::from("0007.batch"),
        PathBuf::from("junk.batch"),
        PathBuf::from(""),
    ];
    assert_eq!(next_counter(&batches), NEXT_AFTER_SEVEN);
    Ok(())
}


#[test]
fn a_full_buffer_reports_saturation_and_stores_nothing() -> TestResult {
    let dir = tempdir()?;
    assert!(matches!(
        enqueue(dir.path(), "[1]", MAX_BYTES, &mut create_file, &mut sync_path)?,
        Enqueued::Stored(_)
    ));
    assert_eq!(
        enqueue(dir.path(), "[22]", SMALL_BATCH_BYTES, &mut create_file, &mut sync_path)?,
        Enqueued::Saturated
    );
    assert_eq!(list_batches(dir.path())?.len(), 1);
    assert!(matches!(
        enqueue(dir.path(), "[2]", TIGHT_LIMIT, &mut create_file, &mut sync_path)?,
        Enqueued::Stored(_)
    ));
    Ok(())
}


#[test]
fn a_failing_writer_is_an_io_error() -> TestResult {
    let mut full: &mut [u8] = &mut [];
    assert!(matches!(write_batch(&mut full, "[1]"), Err(ExportError::Io { .. })));
    let mut empty: &mut [u8] = &mut [];
    let mut buffered = io::BufWriter::new(&mut empty);
    assert!(matches!(write_batch(&mut buffered, "[1]"), Err(ExportError::Io { .. })));
    Ok(())
}


#[test]
fn drain_delivers_oldest_first_and_deletes() -> TestResult {
    let dir = tempdir()?;
    enqueue(dir.path(), "[1]", MAX_BYTES, &mut create_file, &mut sync_path)?;
    enqueue(dir.path(), "[2]", MAX_BYTES, &mut create_file, &mut sync_path)?;
    let mut seen = Vec::new();
    let delivered = drain(dir.path(), &mut |body| {
        seen.push(body.to_string());
        Ok(())
    })?;
    assert_eq!((delivered, seen), (BATCHES_BUFFERED, vec!["[1]".to_string(), "[2]".to_string()]));
    assert!(list_batches(dir.path())?.is_empty());
    Ok(())
}


#[test]
fn drain_stops_at_the_first_failure_and_keeps_the_rest() -> TestResult {
    let dir = tempdir()?;
    enqueue(dir.path(), "[1]", MAX_BYTES, &mut create_file, &mut sync_path)?;
    enqueue(dir.path(), "[2]", MAX_BYTES, &mut create_file, &mut sync_path)?;
    let outcome = drain(dir.path(), &mut |_body| Err(ExportError::Exhausted { attempts: 1, source: None }));
    assert!(matches!(outcome, Err(ExportError::Exhausted { .. })));
    assert_eq!(list_batches(dir.path())?.len(), BATCHES_BUFFERED);
    Ok(())
}


#[test]
fn an_unreadable_batch_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    fs::write(dir.path().join("0.batch"), INVALID_UTF8)?;
    assert!(matches!(drain(dir.path(), &mut |_body| Ok(())), Err(ExportError::Io { .. })));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_dangling_batch_cannot_be_measured() -> TestResult {
    let dir = tempdir()?;
    std::os::unix::fs::symlink(dir.path().join("nowhere"), dir.path().join("0.batch"))?;
    assert!(matches!(buffered_bytes(dir.path()), Err(ExportError::Io { .. })));
    Ok(())
}


#[test]
fn a_file_in_place_of_the_directory_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("file");
    fs::write(&file, "x")?;
    assert!(matches!(list_batches(&file), Err(ExportError::Io { .. })));
    assert!(matches!(buffered_bytes(&file), Err(ExportError::Io { .. })));
    assert!(matches!(drain(&file, &mut |_body| Ok(())), Err(ExportError::Io { .. })));
    assert!(matches!(
        enqueue(&file, "[1]", MAX_BYTES, &mut create_file, &mut sync_path),
        Err(ExportError::Io { .. })
    ));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_read_only_directory_fails_creation_and_removal() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    const READ_ONLY_MODE: u32 = 0o555;
    const WRITABLE_MODE: u32 = 0o755;
    let dir = tempdir()?;
    let path = dir.path().to_path_buf();
    fs::set_permissions(&path, fs::Permissions::from_mode(READ_ONLY_MODE))?;
    let create = enqueue(&path, "[1]", MAX_BYTES, &mut create_file, &mut sync_path);
    fs::set_permissions(&path, fs::Permissions::from_mode(WRITABLE_MODE))?;
    assert!(matches!(create, Err(ExportError::Io { .. })));
    enqueue(&path, "[1]", MAX_BYTES, &mut create_file, &mut sync_path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(READ_ONLY_MODE))?;
    let removal = drain(&path, &mut |_body| Ok(()));
    fs::set_permissions(&path, fs::Permissions::from_mode(WRITABLE_MODE))?;
    assert!(matches!(removal, Err(ExportError::Io { .. })));
    Ok(())
}


#[test]
fn an_injected_writer_that_fails_is_an_io_error_and_leaves_no_batch() -> TestResult {
    let dir = tempdir()?;
    let buffer = dir.path().join("buffer");
    let mut full = |_path: &Path| -> io::Result<Box<dyn Write>> {
        let empty: &'static mut [u8] = &mut [];
        Ok(Box::new(empty))
    };
    assert!(matches!(
        enqueue(&buffer, "[1]", MAX_BYTES, &mut full, &mut sync_path),
        Err(ExportError::Io { .. })
    ));
    let mut refusing = |_path: &Path| -> io::Result<Box<dyn Write>> { Err(io::Error::other("no space")) };
    assert!(matches!(
        enqueue(&buffer, "[1]", MAX_BYTES, &mut refusing, &mut sync_path),
        Err(ExportError::Io { .. })
    ));
    assert!(list_batches(&buffer)?.is_empty());
    Ok(())
}


#[test]
fn a_batch_that_cannot_be_fsynced_is_an_io_error_and_never_counts_as_buffered() -> TestResult {
    let dir = tempdir()?;
    let mut failing_sync = |_path: &Path| -> io::Result<()> { Err(io::Error::other("fsync refused")) };
    assert!(matches!(
        enqueue(dir.path(), "[1]", MAX_BYTES, &mut create_file, &mut failing_sync),
        Err(ExportError::Io { .. })
    ));
    assert!(list_batches(dir.path())?.is_empty());
    Ok(())
}


#[test]
fn a_directory_that_cannot_be_fsynced_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    let mut calls = u32::MIN;
    let mut failing_directory = |path: &Path| -> io::Result<()> {
        calls += 1;
        if path.is_dir() {
            Err(io::Error::other("fsync refused"))
        } else {
            Ok(())
        }
    };
    assert!(matches!(
        enqueue(dir.path(), "[1]", MAX_BYTES, &mut create_file, &mut failing_directory),
        Err(ExportError::Io { .. })
    ));
    assert_eq!(calls, FSYNC_CALLS);
    Ok(())
}


#[test]
fn production_fsync_handles_files_and_directories() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("f");
    fs::write(&file, "x")?;
    sync_path(&file)?;
    sync_path(dir.path())?;
    assert!(sync_path(&dir.path().join("absent")).is_err());
    Ok(())
}


#[test]
fn a_batch_that_cannot_be_renamed_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    let mut discarding = |_path: &Path| -> io::Result<Box<dyn Write>> { Ok(Box::new(io::sink())) };
    assert!(matches!(
        enqueue(dir.path(), "[1]", MAX_BYTES, &mut discarding, &mut |_path| Ok(())),
        Err(ExportError::Io { .. })
    ));
    Ok(())
}


#[cfg(unix)]
#[test]
fn an_unlistable_directory_is_an_io_error() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    const NO_READ_MODE: u32 = 0o333;
    const WRITABLE_MODE: u32 = 0o755;
    let dir = tempdir()?;
    let path = dir.path().to_path_buf();
    fs::set_permissions(&path, fs::Permissions::from_mode(NO_READ_MODE))?;
    let outcome = enqueue(&path, "[1]", MAX_BYTES, &mut create_file, &mut sync_path);
    fs::set_permissions(&path, fs::Permissions::from_mode(WRITABLE_MODE))?;
    assert!(matches!(outcome, Err(ExportError::Io { .. })));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_dangling_batch_fails_the_size_check() -> TestResult {
    let dir = tempdir()?;
    std::os::unix::fs::symlink(dir.path().join("nowhere"), dir.path().join("0.batch"))?;
    assert!(matches!(
        enqueue(dir.path(), "[1]", MAX_BYTES, &mut create_file, &mut sync_path),
        Err(ExportError::Io { .. })
    ));
    Ok(())
}
