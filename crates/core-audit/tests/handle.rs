#![cfg(unix)]


#[path = "support/types.rs"]
mod types;


use core_audit::cli::sample_entry;
use core_audit::cli::{export_file, verify_file};
use core_audit::error::AuditError;
use core_audit::log::{append_declared, check_private, handle_facts, judge_handle, open_file_log, owner_only, HandleFacts};
use core_audit::verify::{verify_capped, MAX_RECORD_BYTES};
use std::fs;
use std::io::{Cursor, Read};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;
use types::TestResult;


const OWN_UID: u32 = 1000;


const OTHER_UID: u32 = 1001;


const GROUP_READABLE: u32 = 0o640;


const OWNER_ONLY: u32 = 0o600;


const GROUP_OTHER: u32 = 0o077;


const PRIVATE_MODE: u32 = 0o100_600;


const TWO_LINKS: u64 = 2;


fn facts() -> HandleFacts {
    HandleFacts {
        regular: true,
        owner: OWN_UID,
        links: 1,
        mode: PRIVATE_MODE,
    }
}


fn fifo_at(path: &Path) -> TestResult {
    assert!(Command::new("mkfifo").arg("-m").arg("600").arg(path).status()?.success());
    Ok(())
}


#[test]
fn a_fifo_is_refused_without_blocking() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    fifo_at(&path)?;
    assert!(matches!(open_file_log(&path), Err(AuditError::NotRegularFile)));
    Ok(())
}


#[test]
fn a_symlink_is_refused_whatever_it_points_at() -> TestResult {
    let dir = tempdir()?;
    let fifo = dir.path().join("fifo");
    fifo_at(&fifo)?;
    let to_fifo = dir.path().join("to_fifo.log");
    symlink(&fifo, &to_fifo)?;
    let to_device = dir.path().join("to_zero.log");
    symlink("/dev/zero", &to_device)?;
    let regular = dir.path().join("real.log");
    fs::write(&regular, b"")?;
    fs::set_permissions(&regular, fs::Permissions::from_mode(OWNER_ONLY))?;
    let to_regular = dir.path().join("to_real.log");
    symlink(&regular, &to_regular)?;
    for link in [&to_fifo, &to_device, &to_regular] {
        assert!(matches!(open_file_log(link), Err(AuditError::SymlinkRefused)));
    }
    Ok(())
}


#[test]
fn a_directory_is_refused_and_a_missing_parent_is_an_io_error() -> TestResult {
    let dir = tempdir()?;
    assert!(matches!(open_file_log(dir.path()), Err(AuditError::NotRegularFile)));
    assert!(matches!(
        open_file_log(&dir.path().join("absent").join("audit.log")),
        Err(AuditError::Io(_))
    ));
    Ok(())
}


#[test]
fn a_file_with_two_links_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    open_file_log(&path)?;
    fs::hard_link(&path, dir.path().join("second.log"))?;
    assert!(matches!(open_file_log(&path), Err(AuditError::LinkedFile { links: TWO_LINKS })));
    Ok(())
}


#[test]
fn a_group_readable_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    open_file_log(&path)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(GROUP_READABLE))?;
    assert!(matches!(
        open_file_log(&path),
        Err(AuditError::InsecurePermissions { mode: GROUP_READABLE })
    ));
    Ok(())
}


const THREE_RECORDS: usize = 3;


const FOURTH_LINE: usize = 4;


const MANY_RECORDS: usize = 300;


#[test]
fn a_record_over_the_bound_is_refused_by_line_and_exactly_at_it_is_not() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    let log = open_file_log(&path)?;
    (0..THREE_RECORDS).try_for_each(|index| append_declared(&log, sample_entry(index), &["name"]).map(|_| ()))?;
    let text = fs::read_to_string(&path)?;
    let longest = text.lines().map(|line| line.len() + 1).max().ok_or("empty")?;
    assert!(verify_capped(Cursor::new(text.as_bytes()), None, longest).is_ok());
    let first = text.lines().next().ok_or("empty")?.len() + 1;
    let refused = verify_capped(Cursor::new(text.as_bytes()), None, first - 1).err().ok_or("accepted")?;
    assert!(matches!(refused, AuditError::RecordTooLong { line: 1, .. }));
    assert!(!format!("{refused} {refused:?}").contains("visible"));
    let tail = format!("{}{}", text, "x".repeat(longest + 1));
    assert!(matches!(
        verify_capped(Cursor::new(tail.as_bytes()), None, longest),
        Err(AuditError::RecordTooLong { line: FOURTH_LINE, .. })
    ));
    Ok(())
}


#[test]
fn a_large_log_opens_and_verifies_with_no_size_cap() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    let log = open_file_log(&path)?;
    (0..MANY_RECORDS).try_for_each(|index| append_declared(&log, sample_entry(index), &["name"]).map(|_| ()))?;
    drop(log);
    open_file_log(&path)?;
    let mut out = Vec::new();
    verify_file(&path.display().to_string(), None, &mut out)?;
    assert!(String::from_utf8(out)?.starts_with("ok 300 records"));
    Ok(())
}


#[derive(Debug)]
pub struct HugeLengthReader {
    pub inner: Cursor<Vec<u8>>,
    pub reported_length: u64,
}


impl Read for HugeLengthReader {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.inner.read(buffer)
    }
}


const REPORTED_LENGTH: u64 = 1 << 40;


#[test]
fn verification_takes_no_length_into_account() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    let log = open_file_log(&path)?;
    (0..THREE_RECORDS).try_for_each(|index| append_declared(&log, sample_entry(index), &["name"]).map(|_| ()))?;
    let reader = HugeLengthReader {
        inner: Cursor::new(fs::read(&path)?),
        reported_length: REPORTED_LENGTH,
    };
    assert!(reader.reported_length > MAX_RECORD_BYTES as u64);
    assert_eq!(core_audit::verify::verify(std::io::BufReader::new(reader), None)?.records, THREE_RECORDS);
    Ok(())
}


#[test]
fn a_device_named_as_the_log_is_refused_and_a_missing_file_is_created() -> TestResult {
    assert!(matches!(open_file_log(Path::new("/dev/ptmx")), Err(AuditError::NotRegularFile)));
    let dir = tempdir()?;
    let path = dir.path().join("fresh.log");
    open_file_log(&path)?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & GROUP_OTHER, 0);
    assert!(matches!(open_file_log(&path.join("below")), Err(AuditError::Io(_))));
    Ok(())
}


#[test]
fn an_oversized_record_is_refused_before_it_is_written() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    let log = open_file_log(&path)?;
    let mut entry = sample_entry(0);
    entry.target = "t".repeat(MAX_RECORD_BYTES);
    assert!(matches!(append_declared(&log, entry, &["name"]), Err(AuditError::RecordTooLarge { .. })));
    assert_eq!(fs::metadata(&path)?.len(), 0);
    Ok(())
}


#[test]
fn verify_and_export_refuse_a_fifo_a_symlink_and_a_loose_mode_without_blocking() -> TestResult {
    let dir = tempdir()?;
    let fifo = dir.path().join("fifo");
    fifo_at(&fifo)?;
    let link = dir.path().join("link");
    symlink(&fifo, &link)?;
    let loose = dir.path().join("loose");
    fs::write(&loose, b"")?;
    fs::set_permissions(&loose, fs::Permissions::from_mode(GROUP_READABLE))?;
    let mut out = Vec::new();
    assert!(matches!(
        verify_file(&fifo.display().to_string(), None, &mut out),
        Err(AuditError::NotRegularFile)
    ));
    assert!(matches!(
        export_file(&fifo.display().to_string(), None, &mut out),
        Err(AuditError::NotRegularFile)
    ));
    assert!(matches!(
        verify_file(&link.display().to_string(), None, &mut out),
        Err(AuditError::SymlinkRefused)
    ));
    assert!(matches!(
        verify_file(&loose.display().to_string(), None, &mut out),
        Err(AuditError::InsecurePermissions { .. })
    ));
    Ok(())
}


#[test]
fn the_judgement_names_each_refusal() -> TestResult {
    assert!(judge_handle(&facts(), OWN_UID).is_ok());
    let not_regular = HandleFacts { regular: false, ..facts() };
    assert!(matches!(judge_handle(&not_regular, OWN_UID), Err(AuditError::NotRegularFile)));
    assert!(matches!(
        judge_handle(&facts(), OTHER_UID),
        Err(AuditError::ForeignOwner {
            owner: OWN_UID,
            expected: OTHER_UID
        })
    ));
    let linked = HandleFacts { links: 0, ..facts() };
    assert!(matches!(judge_handle(&linked, OWN_UID), Err(AuditError::LinkedFile { links: 0 })));
    Ok(())
}


#[test]
fn the_facts_come_from_the_handle() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("plain");
    fs::write(&path, b"abc")?;
    let found = handle_facts(&fs::File::open(&path)?.metadata()?);
    assert!(found.regular && found.links == 1);
    Ok(())
}


#[test]
fn owner_only_creates_a_file_without_group_or_other_bits() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("private");
    owner_only(fs::OpenOptions::new().write(true).create(true)).open(&path)?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & GROUP_OTHER, 0);
    Ok(())
}


#[test]
fn check_private_accepts_a_private_file_and_names_a_loose_mode() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("key");
    fs::write(&path, b"")?;
    fs::set_permissions(&path, fs::Permissions::from_mode(OWNER_ONLY))?;
    check_private(&fs::File::open(&path)?)?;
    fs::set_permissions(&path, fs::Permissions::from_mode(GROUP_READABLE))?;
    assert!(matches!(
        check_private(&fs::File::open(&path)?),
        Err(AuditError::InsecurePermissions { mode: GROUP_READABLE })
    ));
    Ok(())
}
