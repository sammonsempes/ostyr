use crate::spool_refused::{captured_log, no_old_file, ATTEMPTS, NEW_BYTES};
use crate::types::TestResult;
use agent_channel::spool::{
    append_back, candidate_of, clear_leftover, create_temporary, create_temporary_with, file_kind, lock_quarantine, open_lock_file, open_regular,
    read_sequence, refusal_kind, remove_regular_file, remove_stale_temporaries, rewrite_lines, rewrite_quarantine, rewrite_quarantine_with,
    scan_stale, write_sequence, write_temporary, Candidate, SequenceState, LEFTOVER_TEXT, MAX_REJECTED_BYTES, MAX_REJECTED_LINES, MAX_STALE_ENTRIES,
    NOT_REGULAR_TEXT, TEMPORARY_RACED_TEXT,
};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use tempfile::tempdir;


const SEQUENCE_STATE: SequenceState = SequenceState { used: 5, count: 2 };


const SENDING_BYTES: u64 = 2;


const PIPE_MODE: u32 = 0o600;


const WIDE_BOUND: usize = 10;


const SKIPPED_ENTRIES: u64 = 3;


const MARKER: &str = "TARGETMARK";


fn io_error(code: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(code.raw_os_error())
}


fn never_clears(_: &Path) -> io::Result<()> {
    Ok(())
}


fn refuse_removal(_: &Path) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::PermissionDenied))
}


fn candidate(name: &str, is_file: bool) -> Candidate {
    Candidate {
        name: name.into(),
        path: PathBuf::from(name),
        is_file,
    }
}


#[test]
fn a_symlink_at_the_sequence_temporary_never_reaches_its_target() -> TestResult {
    let dir = tempdir()?;
    let target = dir.path().join("target");
    fs::write(&target, MARKER)?;
    let sequence = dir.path().join("sequence");
    std::os::unix::fs::symlink(&target, dir.path().join("sequence.tmp"))?;
    write_sequence(&sequence, SEQUENCE_STATE)?;
    assert_eq!(fs::read_to_string(&target)?, MARKER);
    assert_eq!(read_sequence(&sequence)?, SEQUENCE_STATE);
    Ok(())
}


#[test]
fn a_symlink_at_the_sending_temporary_never_reaches_its_target() -> TestResult {
    let dir = tempdir()?;
    let target = dir.path().join("target");
    fs::write(&target, MARKER)?;
    let sending = dir.path().join("spool.sending");
    fs::write(&sending, "a\n")?;
    std::os::unix::fs::symlink(&target, dir.path().join("spool.sending.tmp"))?;
    assert!(rewrite_lines(&sending, &["b".to_owned()], SENDING_BYTES)?);
    assert_eq!(fs::read_to_string(&target)?, MARKER);
    assert_eq!(fs::read_to_string(&sending)?, "b\n");
    Ok(())
}


#[test]
fn a_dangling_symlink_and_a_pipe_at_a_temporary_are_replaced_by_identity() -> TestResult {
    let dir = tempdir()?;
    let temporary = dir.path().join("sequence.tmp");
    std::os::unix::fs::symlink(dir.path().join("missing"), &temporary)?;
    write_sequence(&dir.path().join("sequence"), SEQUENCE_STATE)?;
    assert!(!dir.path().join("missing").exists());
    let sending = dir.path().join("spool.sending");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        dir.path().join("spool.sending.tmp"),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_bits_truncate(PIPE_MODE),
        0,
    )?;
    let written = write_temporary(&sending, &["x".to_owned()])?;
    assert_eq!(fs::read_to_string(written)?, "x\n");
    Ok(())
}


#[test]
fn a_directory_at_a_temporary_is_a_fixed_error_naming_its_kind() -> TestResult {
    let dir = tempdir()?;
    fs::create_dir(dir.path().join("sequence.tmp"))?;
    let error = write_sequence(&dir.path().join("sequence"), SEQUENCE_STATE).err().ok_or("accepted")?;
    assert!(
        error.to_string().contains(LEFTOVER_TEXT) && error.to_string().contains("directory"),
        "{error}"
    );
    fs::create_dir(dir.path().join("spool.tmp"))?;
    let write = write_temporary(&dir.path().join("spool"), &[]).err().ok_or("accepted")?;
    assert!(write.to_string().contains("directory"), "{write}");
    assert!(dir.path().join("sequence.tmp").is_dir());
    Ok(())
}


#[test]
fn a_leftover_that_cannot_be_cleared_names_its_kind_and_a_temporary_that_reappears_fails() -> TestResult {
    let dir = tempdir()?;
    let leftover = dir.path().join("leftover");
    fs::write(&leftover, "")?;
    assert!(clear_leftover(&leftover).is_ok());
    let gone = clear_leftover(&leftover).err().ok_or("accepted")?;
    assert!(gone.to_string().contains("missing"), "{gone}");
    let again = dir.path().join("again");
    fs::write(&again, "")?;
    let raced = create_temporary_with(&again, never_clears).err().ok_or("accepted")?;
    assert!(raced.to_string().contains(TEMPORARY_RACED_TEXT), "{raced}");
    assert!(create_temporary(&leftover).is_ok());
    Ok(())
}


#[test]
fn the_kind_of_an_entry_is_named_from_its_type_and_its_open_error() -> TestResult {
    let dir = tempdir()?;
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(dir.path(), &link)?;
    assert_eq!(file_kind(fs::symlink_metadata(&link)?.file_type()), "symlink");
    assert_eq!(file_kind(fs::metadata(dir.path())?.file_type()), "directory");
    assert_eq!(file_kind(fs::metadata("/dev/null")?.file_type()), "special file");
    assert_eq!(refusal_kind(&io_error(rustix::io::Errno::LOOP)), Some("symlink"));
    assert_eq!(refusal_kind(&io_error(rustix::io::Errno::NXIO)), Some("pipe or socket"));
    assert_eq!(refusal_kind(&io_error(rustix::io::Errno::ISDIR)), Some("directory"));
    assert_eq!(refusal_kind(&io_error(rustix::io::Errno::ACCESS)), Some("foreign file"));
    assert_eq!(refusal_kind(&io_error(rustix::io::Errno::WOULDBLOCK)), Some("leased file"));
    assert_eq!(refusal_kind(&io_error(rustix::io::Errno::NOSPC)), None);
    Ok(())
}


#[test]
fn a_spool_that_is_a_link_or_a_pipe_is_refused_by_kind_and_never_followed() -> TestResult {
    let dir = tempdir()?;
    let target = dir.path().join("target");
    fs::write(&target, MARKER)?;
    let spool = dir.path().join("spool");
    std::os::unix::fs::symlink(&target, &spool)?;
    let error = append_back(vec![Ok("line".to_owned())].into_iter(), &spool).err().ok_or("accepted")?;
    assert!(
        error.to_string().contains(NOT_REGULAR_TEXT) && error.to_string().contains("symlink"),
        "{error}"
    );
    assert_eq!(fs::read_to_string(&target)?, MARKER);
    fs::remove_file(&spool)?;
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &spool,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_bits_truncate(PIPE_MODE),
        0,
    )?;
    let pipe = append_back(vec![Ok("line".to_owned())].into_iter(), &spool).err().ok_or("accepted")?;
    assert!(pipe.to_string().contains("special file"), "{pipe}");
    assert!(open_regular(OpenOptions::new().read(true), Path::new("/nonexistent-t590b")).is_err());
    Ok(())
}


#[test]
fn a_hard_linked_lock_disables_the_quarantine_and_a_missing_directory_does_too() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    let lock = dir.path().join("spool.rejected.lock");
    fs::write(&lock, "")?;
    fs::hard_link(&lock, dir.path().join("elsewhere"))?;
    let added = vec!["x".to_owned()];
    let outcome = rewrite_quarantine_with(
        &rejected,
        &added,
        NEW_BYTES,
        (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
        (no_old_file, ATTEMPTS),
    )?;
    assert_eq!(outcome, None);
    assert!(!rejected.exists());
    let missing = dir.path().join("missing-directory").join("spool.rejected");
    assert!(lock_quarantine(&missing, ATTEMPTS)?.is_none());
    assert!(open_lock_file(&missing.with_extension("lock"))?.is_none());
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(
        log.contains("quarantine lock is not usable") && log.contains("quarantine lock not opened"),
        "{log}"
    );
    Ok(())
}


fn make_directory_then_say_none(path: &Path) -> io::Result<Option<File>> {
    fs::create_dir(path)?;
    Ok(None)
}


#[test]
fn a_directory_created_at_the_quarantine_after_the_check_disables_the_quarantine() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    let added = vec!["x".to_owned()];
    let outcome = rewrite_quarantine_with(
        &rejected,
        &added,
        NEW_BYTES,
        (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
        (make_directory_then_say_none, ATTEMPTS),
    )?;
    assert_eq!(outcome, None);
    assert!(rejected.is_dir());
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("quarantine rewrite failed, quarantine disabled for this run"), "{log}");
    Ok(())
}


#[test]
fn the_stale_scan_skips_and_counts_every_unreadable_or_unremovable_entry() -> TestResult {
    let (captured, _guard) = captured_log();
    let entries = vec![
        Err(io::Error::from(io::ErrorKind::NotFound)),
        Ok(candidate("other", true)),
        Ok(candidate(".p-dir", false)),
        Ok(candidate(".p-file", true)),
    ];
    let counts = scan_stale(&mut entries.into_iter(), ".p-", refuse_removal, WIDE_BOUND);
    assert_eq!(counts, (0, SKIPPED_ENTRIES));
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("scan entry not read") && log.contains("not removed"), "{log}");
    let removed = scan_stale(&mut vec![Ok(candidate(".p-1", true))].into_iter(), ".p-", never_clears, WIDE_BOUND);
    assert_eq!(removed, (1, 0));
    Ok(())
}


const SMALL_BOUND: usize = 3;


const SMALL_BOUND_TEXT: &str = "bound=3";


const STALE_FILES: usize = 10;


#[test]
fn the_stale_scan_reads_at_most_its_bound_and_names_it() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    (0..STALE_FILES).try_for_each(|index| fs::write(dir.path().join(format!(".p-{index}")), ""))?;
    let (removed, skipped) = remove_stale_temporaries(dir.path(), ".p-", remove_regular_file, SMALL_BOUND)?;
    assert_eq!((removed, skipped), (SMALL_BOUND as u64, 0));
    assert_eq!(fs::read_dir(dir.path())?.count(), STALE_FILES - SMALL_BOUND);
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("MAX_STALE_ENTRIES") && log.contains(SMALL_BOUND_TEXT), "{log}");
    let entry = fs::read_dir(dir.path())?.next().ok_or("empty")??;
    assert!(candidate_of(entry)?.is_file);
    Ok(())
}


const EXTRA_STALE: usize = 7;


const LOCK_ENTRY: usize = 1;


#[test]
fn a_rewrite_reads_at_most_the_production_stale_bound() -> TestResult {
    let dir = tempdir()?;
    let quarantine = dir.path().join("spool.rejected");
    (0..MAX_STALE_ENTRIES + EXTRA_STALE).try_for_each(|index| fs::write(dir.path().join(format!(".spool.rejected.quarantine-{index}")), ""))?;
    let lines = vec!["x".to_owned()];
    assert!(rewrite_quarantine(&quarantine, &lines, 1, (MAX_REJECTED_BYTES, MAX_REJECTED_LINES))?.is_some());
    let leftovers = fs::read_dir(dir.path())?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with(".spool.rejected.quarantine-"))
        .count();
    assert_eq!(leftovers, EXTRA_STALE + LOCK_ENTRY);
    Ok(())
}


const FREE_DESCRIPTORS_VARIABLE: &str = "T590B_FREE_DESCRIPTORS";


const CHILD_TEST: &str = "spool_sibling::descriptor_child_when_asked";


const DESCRIPTOR_LIMIT: u64 = 128;


const OLD_QUARANTINE: &str = "OLDLINE\n";


fn restrict_descriptors(free: usize) -> io::Result<Vec<File>> {
    let limit = rustix::process::Rlimit {
        current: Some(DESCRIPTOR_LIMIT),
        maximum: rustix::process::getrlimit(rustix::process::Resource::Nofile).maximum,
    };
    rustix::process::setrlimit(rustix::process::Resource::Nofile, limit)?;
    let mut held = (0..DESCRIPTOR_LIMIT)
        .map(|_| File::open("/dev/null"))
        .take_while(Result::is_ok)
        .collect::<io::Result<Vec<_>>>()?;
    held.truncate(held.len().saturating_sub(free));
    Ok(held)
}


#[test]
fn descriptor_child_when_asked() -> TestResult {
    if let Ok(text) = std::env::var(FREE_DESCRIPTORS_VARIABLE) {
        let dir = tempdir()?;
        let rejected = dir.path().join("spool.rejected");
        fs::write(&rejected, OLD_QUARANTINE)?;
        let held = restrict_descriptors(text.parse()?)?;
        let outcome = rewrite_quarantine(&rejected, &["NEWLINE".to_owned()], NEW_BYTES, (MAX_REJECTED_BYTES, MAX_REJECTED_LINES))?;
        drop(held);
        assert_eq!(outcome, None);
        assert_eq!(fs::read_to_string(&rejected)?, OLD_QUARANTINE);
    }
    Ok(())
}


#[test]
fn running_out_of_descriptors_disables_the_quarantine_and_keeps_the_old_file() -> TestResult {
    let me = std::env::current_exe()?;
    ["0", "2"].iter().try_for_each(|free| -> TestResult {
        let output = std::process::Command::new(&me)
            .args(["--exact", CHILD_TEST, "--test-threads=1", "--nocapture"])
            .env(FREE_DESCRIPTORS_VARIABLE, free)
            .output()?;
        assert!(output.status.success(), "free={free} {}", String::from_utf8_lossy(&output.stdout));
        Ok(())
    })
}
