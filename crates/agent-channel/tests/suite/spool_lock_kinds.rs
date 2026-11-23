use crate::harness::long_tempdir;
use crate::spool_append::agent_file;
use crate::spool_refused::{captured_log, no_old_file, texts, ATTEMPTS, BAD_LINE, NEW_BYTES};
use crate::types::TestResult;
use agent_channel::spool::{claim_spool, is_not_a_regular_file, rewrite_quarantine, rewrite_quarantine_with, MAX_REJECTED_BYTES, MAX_REJECTED_LINES};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{symlink, OpenOptionsExt, PermissionsExt};
use std::path::Path;


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
        let dir = long_tempdir()?;
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
            log.contains("quarantine lock is not usable") && log.contains("refused=1"),
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
        let dir = long_tempdir()?;
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
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    make_fifo(&dir.path().join("spool.rejected.lock"))?;
    fs::create_dir(dir.path().join("spool.rejected"))?;
    fs::write(&file.spool_file, "good\ntorn")?;
    let claimed = claim_spool(&file)?;
    assert_eq!(texts(&claimed.batches), vec!["good".to_owned()]);
    Ok(())
}


#[test]
fn a_lock_in_an_unusable_directory_disables_the_quarantine_never_fails_the_claim() -> TestResult {
    let dir = long_tempdir()?;
    let blocker = dir.path().join("blocker");
    fs::write(&blocker, "file")?;
    let added = vec!["x".to_owned()];
    let result = rewrite_quarantine_with(
        &blocker.join("spool.rejected"),
        &added,
        NEW_BYTES,
        (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
        (no_old_file, ATTEMPTS),
    )?;
    assert_eq!(result, None);
    Ok(())
}


const FOREIGN_UID: u32 = 65534;


const STICKY_WORLD_WRITABLE: u32 = 0o1777;


#[test]
fn a_socket_at_the_quarantine_is_ignored_and_replaced_for_the_claim_the_tail_cut_and_the_rewrite() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let rejected = dir.path().join("spool.rejected");
    make_node(&rejected, rustix::fs::FileType::Socket)?;
    let mut spool = b"good\n".to_vec();
    spool.extend_from_slice(BAD_LINE);
    spool.extend_from_slice(b"good2\ntorn");
    fs::write(&file.spool_file, spool)?;
    let claimed = claim_spool(&file)?;
    assert_eq!(texts(&claimed.batches), vec!["good".to_owned(), "good2".to_owned()]);
    let torn = dir.path().join("torn-spool");
    fs::write(&torn, "a\nzzz")?;
    make_node(&dir.path().join("torn-spool.rejected"), rustix::fs::FileType::Socket)?;
    assert!(agent_channel::spool::append_back(vec![Ok("b".to_owned())].into_iter(), &torn)?);
    assert_eq!(fs::read_to_string(&torn)?, "a\nb\n");
    fs::remove_file(&rejected)?;
    make_node(&rejected, rustix::fs::FileType::Socket)?;
    let outcome = rewrite_quarantine(&rejected, &["x".to_owned()], NEW_BYTES, (MAX_REJECTED_BYTES, MAX_REJECTED_LINES))?;
    assert_eq!(outcome, Some(0));
    assert_eq!(fs::read_to_string(&rejected)?, "x\n");
    Ok(())
}


#[test]
fn a_permission_refusal_of_the_protected_file_rules_means_not_a_regular_file() -> TestResult {
    assert!(is_not_a_regular_file(&io::Error::from_raw_os_error(
        rustix::io::Errno::ACCESS.raw_os_error()
    )));
    assert!(is_not_a_regular_file(&io::Error::from_raw_os_error(
        rustix::io::Errno::PERM.raw_os_error()
    )));
    assert!(is_not_a_regular_file(&io::Error::from_raw_os_error(
        rustix::io::Errno::NXIO.raw_os_error()
    )));
    assert!(!is_not_a_regular_file(&io::Error::from_raw_os_error(
        rustix::io::Errno::NOSPC.raw_os_error()
    )));
    assert!(!is_not_a_regular_file(&io::Error::from(io::ErrorKind::NotFound)));
    Ok(())
}


#[test]
fn a_foreign_entry_at_the_lock_in_a_sticky_directory_never_stops_the_claim_or_the_tail_cut() -> TestResult {
    [LockKind::FifoWithoutReader, LockKind::Socket].iter().try_for_each(|kind| -> TestResult {
        let dir = long_tempdir()?;
        fs::set_permissions(dir.path(), fs::Permissions::from_mode(STICKY_WORLD_WRITABLE))?;
        let file = agent_file(dir.path());
        let lock = dir.path().join("spool.rejected.lock");
        place_lock(*kind, &lock)?;
        let owner = rustix::fs::Uid::from_raw(FOREIGN_UID);
        rustix::fs::chownat(rustix::fs::CWD, &lock, Some(owner), None, rustix::fs::AtFlags::empty())?;
        fs::write(&file.spool_file, "good\ntorn")?;
        let claimed = claim_spool(&file)?;
        assert_eq!(texts(&claimed.batches), vec!["good".to_owned()], "{kind:?}");
        let torn = dir.path().join("torn-spool");
        fs::write(&torn, "a\nzzz")?;
        let torn_lock = dir.path().join("torn-spool.rejected.lock");
        place_lock(*kind, &torn_lock)?;
        rustix::fs::chownat(rustix::fs::CWD, &torn_lock, Some(owner), None, rustix::fs::AtFlags::empty())?;
        assert!(
            agent_channel::spool::append_back(vec![Ok("b".to_owned())].into_iter(), &torn)?,
            "{kind:?}"
        );
        Ok(())
    })
}
