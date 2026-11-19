#![cfg(unix)]


#[path = "support/types.rs"]
mod types;


use core_audit::cli::sample_entry;
use core_audit::cli::{export_file, verify_file};
use core_audit::error::AuditError;
use core_audit::log::{
    append_declared, check_private, create_new, handle_facts, judge_handle, open_file_log, open_file_log_with, open_read_with, open_with, owner_only,
    HandleFacts, Opener, SYSTEM_OPENER,
};
use core_audit::verify::{verify_capped, MAX_RECORD_BYTES};
use rustix::fs::OFlags;
use std::fs;
use std::io::{BufReader, Cursor, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Component, Path};
use std::process::Command;
use std::sync::LazyLock;
use tempfile::tempdir;
use types::TestResult;


const OWN_UID: u32 = 1000;


const OTHER_UID: u32 = 1001;


const WRITE_SEARCH_ONLY: u32 = 0o300;


const OWNER_ALL: u32 = 0o700;


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


const SPARSE_OFFSET: u64 = 1 << 40;


fn seek_reopen(path: &Path, flags: OFlags) -> Result<fs::File, AuditError> {
    let mut file = open_with(path, flags)?;
    file.seek(SeekFrom::Start(SPARSE_OFFSET))?;
    Ok(file)
}


const SEEK_OPENER: Opener = Opener {
    reopen: seek_reopen,
    ..SYSTEM_OPENER
};


#[test]
fn a_real_terabyte_file_opens_and_verifies() -> TestResult {
    let dir = tempdir()?;
    let seed = dir.path().join("seed.log");
    let log = open_file_log(&seed)?;
    (0..THREE_RECORDS).try_for_each(|index| append_declared(&log, sample_entry(index), &["name"]).map(|_| ()))?;
    drop(log);
    let records = fs::read(&seed)?;
    let sparse = dir.path().join("sparse.log");
    drop(open_file_log(&sparse)?);
    let mut handle = fs::OpenOptions::new().write(true).open(&sparse)?;
    handle.set_len(SPARSE_OFFSET)?;
    handle.seek(SeekFrom::Start(SPARSE_OFFSET))?;
    handle.write_all(&records)?;
    drop(handle);
    assert!(fs::metadata(&sparse)?.len() > SPARSE_OFFSET);
    let continued = open_file_log_with(&sparse, &SEEK_OPENER)?;
    append_declared(&continued, sample_entry(THREE_RECORDS), &["name"])?;
    drop(continued);
    let report = core_audit::verify::verify(BufReader::new(open_read_with(&sparse, &SEEK_OPENER)?), None)?;
    assert_eq!(report.records, THREE_RECORDS + 1);
    Ok(())
}


fn proc_missing(_path: &Path, _flags: OFlags) -> Result<fs::File, AuditError> {
    Err(AuditError::Io(std::io::ErrorKind::NotFound.into()))
}


const NO_PROC_OPENER: Opener = Opener {
    reopen: proc_missing,
    ..SYSTEM_OPENER
};


#[test]
fn a_missing_proc_is_a_fixed_error_and_never_a_creation() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    open_file_log(&path)?;
    assert!(matches!(open_file_log_with(&path, &NO_PROC_OPENER), Err(AuditError::ProcUnavailable)));
    assert!(matches!(open_read_with(&path, &NO_PROC_OPENER), Err(AuditError::ProcUnavailable)));
    assert!(open_file_log_with(&path, &NO_PROC_OPENER)
        .err()
        .is_some_and(|error| error.to_string().contains("/proc")));
    Ok(())
}


fn proc_denied(_path: &Path, _flags: OFlags) -> Result<fs::File, AuditError> {
    Err(AuditError::Io(std::io::ErrorKind::PermissionDenied.into()))
}


#[test]
fn another_reopen_failure_keeps_its_kind() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    open_file_log(&path)?;
    let denied = Opener {
        reopen: proc_denied,
        ..SYSTEM_OPENER
    };
    assert!(matches!(
        open_file_log_with(&path, &denied),
        Err(AuditError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied
    ));
    Ok(())
}


#[test]
fn creation_is_exclusive() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    create_new(&path, &SYSTEM_OPENER)?;
    assert!(matches!(
        create_new(&path, &SYSTEM_OPENER),
        Err(AuditError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
    ));
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
    let found = handle_facts(&fs::File::open(&path)?)?;
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


const HIDDEN_PROC: Opener = Opener {
    proc_fd_dir: "/nonexistent-proc/self/fd",
    ..SYSTEM_OPENER
};


#[test]
fn a_hidden_proc_creates_nothing() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    assert!(matches!(open_file_log_with(&path, &HIDDEN_PROC), Err(AuditError::ProcUnavailable)));
    assert!(!path.exists());
    Ok(())
}


const TASK_DIR_OPENER: Opener = Opener {
    reopen: echo_path,
    proc_fd_dir: "/proc/self/task",
    ..SYSTEM_OPENER
};


fn echo_path(path: &Path, _flags: OFlags) -> Result<fs::File, AuditError> {
    Err(AuditError::Io(std::io::Error::other(path.display().to_string())))
}


#[test]
fn the_reopen_path_is_built_from_the_opener_directory() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    let error = open_file_log_with(&path, &TASK_DIR_OPENER).err().ok_or("expected a failure")?;
    assert!(error.to_string().contains("/proc/self/task/"));
    assert!(!path.exists());
    Ok(())
}


const START_COUNT: u8 = 2;


const DENIED_OPENER: Opener = Opener {
    reopen: proc_denied,
    ..SYSTEM_OPENER
};


fn is_denied(result: Result<core_audit::log::AuditLog<fs::File>, AuditError>) -> bool {
    matches!(result, Err(AuditError::Io(error)) if error.kind() == std::io::ErrorKind::PermissionDenied)
}


#[test]
fn a_denied_reopen_fails_a_new_log_like_an_existing_one_and_leaves_nothing() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    (0..START_COUNT).try_for_each(|_| -> TestResult {
        assert!(is_denied(open_file_log_with(&path, &DENIED_OPENER)));
        assert!(!path.exists());
        Ok(())
    })
}


fn replace_with_other_file(proc_path: &Path, flags: OFlags) -> Result<fs::File, AuditError> {
    let name = fs::read_link(proc_path)?;
    fs::remove_file(&name)?;
    fs::write(&name, "other")?;
    proc_denied(proc_path, flags)
}


fn replace_with_symlink(proc_path: &Path, flags: OFlags) -> Result<fs::File, AuditError> {
    let name = fs::read_link(proc_path)?;
    fs::remove_file(&name)?;
    symlink("victim", &name)?;
    proc_denied(proc_path, flags)
}


fn remove_name(proc_path: &Path, flags: OFlags) -> Result<fs::File, AuditError> {
    fs::remove_file(fs::read_link(proc_path)?)?;
    proc_denied(proc_path, flags)
}


#[test]
fn a_name_swapped_after_creation_is_never_removed() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    let swapped = Opener {
        reopen: replace_with_other_file,
        ..SYSTEM_OPENER
    };
    assert!(is_denied(open_file_log_with(&path, &swapped)));
    assert_eq!(fs::read_to_string(&path)?, "other");
    Ok(())
}


#[test]
fn a_symlink_swapped_in_after_creation_is_not_followed_or_removed() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    let victim = dir.path().join("victim");
    fs::write(&victim, "keep")?;
    let swapped = Opener {
        reopen: replace_with_symlink,
        ..SYSTEM_OPENER
    };
    assert!(is_denied(open_file_log_with(&path, &swapped)));
    assert_eq!(fs::read_to_string(&victim)?, "keep");
    assert!(fs::symlink_metadata(&path)?.file_type().is_symlink());
    Ok(())
}


#[test]
fn a_failed_removal_keeps_the_reopen_error() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("audit.log");
    let vanished = Opener {
        reopen: remove_name,
        ..SYSTEM_OPENER
    };
    let refused = tracing::dispatcher::with_default(&LISTENING, || open_file_log_with(&path, &vanished));
    assert!(is_denied(refused));
    assert!(!path.exists());
    Ok(())
}


static LISTENING: LazyLock<tracing::Dispatch> =
    LazyLock::new(|| tracing::Dispatch::new(tracing_subscriber::fmt().with_writer(std::io::sink).finish()));


fn failing_facts_for_marked_name(file: &fs::File) -> std::io::Result<core_audit::log::HandleFacts> {
    let name = fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))?;
    if name.to_string_lossy().contains("facts-fail") {
        Err(std::io::Error::other("injected fstat failure"))
    } else {
        handle_facts(file)
    }
}


#[test]
fn a_failed_first_judge_leaves_no_file() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("facts-fail.log");
    let failing = Opener {
        facts: failing_facts_for_marked_name,
        ..SYSTEM_OPENER
    };
    assert!(matches!(open_file_log_with(&path, &failing), Err(AuditError::Io(_))));
    assert!(!path.exists());
    Ok(())
}


fn rename_parent_then_deny(proc_path: &Path, flags: OFlags) -> Result<fs::File, AuditError> {
    let name = fs::read_link(proc_path)?;
    let parent = name.parent().ok_or(AuditError::SymlinkRefused)?;
    fs::rename(parent, parent.with_extension("moved"))?;
    fs::create_dir(parent)?;
    fs::write(&name, "decoy")?;
    proc_denied(proc_path, flags)
}


#[test]
fn a_parent_renamed_before_the_cleanup_cannot_redirect_the_unlink() -> TestResult {
    let dir = tempdir()?;
    let parent = dir.path().join("logs");
    fs::create_dir(&parent)?;
    let path = parent.join("audit.log");
    let renaming = Opener {
        reopen: rename_parent_then_deny,
        ..SYSTEM_OPENER
    };
    assert!(is_denied(open_file_log_with(&path, &renaming)));
    assert!(!dir.path().join("logs.moved").join("audit.log").exists());
    assert_eq!(fs::read_to_string(&path)?, "decoy");
    Ok(())
}


#[test]
fn a_path_without_a_parent_and_leaf_is_refused_before_any_io() -> TestResult {
    assert!(matches!(
        create_new(Path::new(".."), &SYSTEM_OPENER),
        Err(AuditError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput
    ));
    Ok(())
}


#[test]
fn a_relative_log_name_is_created_below_the_current_directory() -> TestResult {
    let dir = tempdir()?;
    let up = std::env::current_dir()?
        .components()
        .filter(|part| matches!(part, Component::Normal(_)))
        .count();
    let mut relative = (0..up).fold(std::path::PathBuf::new(), |path, _| path.join(".."));
    relative.extend(dir.path().components().filter(|part| matches!(part, Component::Normal(_))));
    let name = relative.join("relative.log");
    assert!(name.is_relative());
    drop(create_new(&name, &SYSTEM_OPENER)?);
    assert!(dir.path().join("relative.log").exists());
    Ok(())
}


#[test]
fn a_name_ending_in_a_directory_form_is_refused_before_any_io() -> TestResult {
    let dir = tempdir()?;
    let slash = format!("{}/", dir.path().join("e.log").display());
    let dot = format!("{}/.", dir.path().join("e.log").display());
    [slash, dot].iter().for_each(|name| {
        assert!(matches!(
            create_new(Path::new(name), &SYSTEM_OPENER),
            Err(AuditError::Io(error)) if error.kind() == std::io::ErrorKind::InvalidInput
        ));
    });
    assert!(!dir.path().join("e.log").exists());
    Ok(())
}


#[test]
fn a_symlinked_parent_creates_and_reopens_the_same_file() -> TestResult {
    let dir = tempdir()?;
    fs::create_dir(dir.path().join("real"))?;
    symlink(dir.path().join("real"), dir.path().join("link"))?;
    let path = dir.path().join("link").join("x.log");
    drop(open_file_log_with(&path, &SYSTEM_OPENER)?);
    assert!(dir.path().join("real").join("x.log").exists());
    drop(open_file_log_with(&path, &SYSTEM_OPENER)?);
    Ok(())
}


#[test]
fn a_parent_without_read_permission_still_creates_the_log() -> TestResult {
    let dir = tempdir()?;
    let parent = dir.path().join("wx");
    fs::create_dir(&parent)?;
    fs::set_permissions(&parent, fs::Permissions::from_mode(WRITE_SEARCH_ONLY))?;
    let created = create_new(&parent.join("a.log"), &SYSTEM_OPENER);
    fs::set_permissions(&parent, fs::Permissions::from_mode(OWNER_ALL))?;
    drop(created?);
    assert!(parent.join("a.log").exists());
    Ok(())
}
