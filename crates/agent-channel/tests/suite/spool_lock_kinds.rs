use crate::spool_append::agent_file;
use crate::spool_refused::{captured_log, no_old_file, texts, ATTEMPTS, BAD_LINE, NEW_BYTES};
use crate::types::TestResult;
use agent_channel::spool::{claim_spool, rewrite_quarantine_with, MAX_REJECTED_BYTES, MAX_REJECTED_LINES};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{symlink, OpenOptionsExt};
use std::path::Path;
use tempfile::tempdir;


#[derive(Clone, Copy, Debug)]
enum LockKind {
    FifoWithoutReader,
    FifoWithReader,
    Directory,
    SymlinkToFifo,
    SymlinkToFile,
    DanglingSymlink,
    Socket,
}


const LOCK_KINDS: [LockKind; 7] = [
    LockKind::FifoWithoutReader,
    LockKind::FifoWithReader,
    LockKind::Directory,
    LockKind::SymlinkToFifo,
    LockKind::SymlinkToFile,
    LockKind::DanglingSymlink,
    LockKind::Socket,
];


const FIFO_MODE: u32 = 0o600;


fn make_node(path: &Path, kind: rustix::fs::FileType) -> io::Result<()> {
    let mode = rustix::fs::Mode::from_bits_truncate(FIFO_MODE);
    Ok(rustix::fs::mknodat(rustix::fs::CWD, path, kind, mode, 0)?)
}


fn make_fifo(path: &Path) -> io::Result<()> {
    make_node(path, rustix::fs::FileType::Fifo)
}


fn open_reader(path: &Path) -> io::Result<File> {
    let flags = rustix::fs::OFlags::NONBLOCK.bits() as i32;
    OpenOptions::new().read(true).custom_flags(flags).open(path)
}


fn place_lock(kind: LockKind, lock: &Path) -> io::Result<Option<File>> {
    let target = lock.with_extension("target");
    let mut reader = None;
    match kind {
        LockKind::FifoWithoutReader => make_fifo(lock)?,
        LockKind::FifoWithReader => {
            make_fifo(lock)?;
            reader = Some(open_reader(lock)?);
        }
        LockKind::Directory => fs::create_dir(lock)?,
        LockKind::SymlinkToFifo => {
            make_fifo(&target)?;
            symlink(&target, lock)?;
        }
        LockKind::SymlinkToFile => {
            fs::write(&target, "")?;
            symlink(&target, lock)?;
        }
        LockKind::DanglingSymlink => symlink(&target, lock)?,
        LockKind::Socket => make_node(lock, rustix::fs::FileType::Socket)?,
    }
    Ok(reader)
}


#[test]
fn a_lock_path_that_is_not_a_regular_file_disables_the_quarantine_and_nothing_waits() -> TestResult {
    LOCK_KINDS.iter().try_for_each(|kind| -> TestResult {
        let (captured, _guard) = captured_log();
        let dir = tempdir()?;
        let rejected = dir.path().join("spool.rejected");
        let reader = place_lock(*kind, &dir.path().join("spool.rejected.lock"))?;
        let added = vec!["MARKERLINE".to_owned()];
        let outcome = rewrite_quarantine_with(
            &rejected,
            &added,
            NEW_BYTES,
            (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
            (no_old_file, ATTEMPTS),
        )?;
        drop(reader);
        assert_eq!(outcome, None, "{kind:?}");
        assert!(!rejected.exists(), "{kind:?}");
        let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
        assert!(
            log.contains("quarantine lock is not a regular file") && log.contains("refused=1"),
            "{kind:?} {log}"
        );
        assert!(!log.contains("MARKERLINE"), "{kind:?} {log}");
        Ok(())
    })
}


#[test]
fn a_lock_path_that_is_not_a_regular_file_never_stops_the_claim_or_the_tail_cut() -> TestResult {
    LOCK_KINDS.iter().try_for_each(|kind| -> TestResult {
        let (captured, _guard) = captured_log();
        let dir = tempdir()?;
        let file = agent_file(dir.path());
        let claim_reader = place_lock(*kind, &dir.path().join("spool.rejected.lock"))?;
        let mut spool = b"good1\n".to_vec();
        spool.extend_from_slice(BAD_LINE);
        spool.extend_from_slice(b"good2\ntorn");
        fs::write(&file.spool_file, spool)?;
        let claimed = claim_spool(&file)?;
        assert_eq!(texts(&claimed.batches), vec!["good1".to_owned(), "good2".to_owned()], "{kind:?}");
        drop(claim_reader);
        let torn = dir.path().join("torn-spool");
        fs::write(&torn, "a\nzzz")?;
        let append_reader = place_lock(*kind, &dir.path().join("torn-spool.rejected.lock"))?;
        let appended = agent_channel::spool::append_back(vec![Ok("b".to_owned())].into_iter(), &torn)?;
        drop(append_reader);
        assert!(appended, "{kind:?}");
        assert_eq!(fs::read_to_string(&torn)?, "a\nb\n", "{kind:?}");
        let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
        assert!(log.contains("unterminated tail dropped, quarantine disabled"), "{kind:?} {log}");
        assert!(!log.contains("set aside in the quarantine"), "{kind:?} {log}");
        assert!(!log.contains("zzz") && !log.contains("MARKER"), "{kind:?} {log}");
        Ok(())
    })
}


#[test]
fn a_fifo_at_the_lock_and_a_directory_at_the_quarantine_together_never_stop_the_claim() -> TestResult {
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    make_fifo(&dir.path().join("spool.rejected.lock"))?;
    fs::create_dir(dir.path().join("spool.rejected"))?;
    fs::write(&file.spool_file, "good\ntorn")?;
    let claimed = claim_spool(&file)?;
    assert_eq!(texts(&claimed.batches), vec!["good".to_owned()]);
    Ok(())
}


#[test]
fn a_lock_in_an_unusable_directory_is_still_an_error() -> TestResult {
    let dir = tempdir()?;
    let blocker = dir.path().join("blocker");
    fs::write(&blocker, "file")?;
    let added = vec!["x".to_owned()];
    let result = rewrite_quarantine_with(
        &blocker.join("spool.rejected"),
        &added,
        NEW_BYTES,
        (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
        (no_old_file, ATTEMPTS),
    );
    assert!(result.is_err());
    Ok(())
}
