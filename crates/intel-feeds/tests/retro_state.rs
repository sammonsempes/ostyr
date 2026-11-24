#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use core_config::secret_file::SecretFileError;
use intel_feeds::limits::MAX_STATE_BYTES;
use intel_feeds::retro_state::{
    open_state_with, read_end, start_of, temporary_options, write_end, write_end_with, StateError, NO_PREVIOUS_RUN, RESUMED, STATE_AHEAD,
    STATE_OTHER_TENANT, STATE_UNREADABLE,
};
use std::fs;
use std::io::{self, ErrorKind};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use tempfile::tempdir;
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;


const END: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


const NOW: OffsetDateTime = datetime!(2026-11-03 12:05:00 UTC);


const END_TEXT: &str = "tenant-a 1793707200";


const BEFORE_EPOCH: OffsetDateTime = datetime!(1969-12-31 23:59:59 UTC);


const ONE_MEGABYTE: usize = 1_048_576;


const FORGED: &str = "tenant-a 253402300799";


const SKEW_EDGE: &str = "tenant-a 1793708100";


const PAST_SKEW_EDGE: &str = "tenant-a 1793708101";


const SKEW_EDGE_SECONDS: i64 = 1_793_708_100;


const END_OF_TIME: OffsetDateTime = datetime!(9999-12-31 23:59:59 UTC);


const TENANT: &str = "tenant-a";


const MODE_MASK: u32 = 0o777;


const OWNER_ONLY: u32 = 0o600;


fn failing_inspection(_file: &fs::File) -> io::Result<fs::Metadata> {
    Err(io::Error::from(ErrorKind::PermissionDenied))
}


fn read(path: &Path) -> Result<Option<OffsetDateTime>, StateError> {
    read_end(path, TENANT, NOW)
}


#[test]
fn an_end_is_written_as_tenant_and_digits_and_read_back() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("retro.state");
    write_end(&path, TENANT, END)?;
    assert_eq!(fs::read_to_string(&path)?, END_TEXT);
    assert_eq!(fs::metadata(&path)?.permissions().mode() & MODE_MASK, OWNER_ONLY);
    assert_eq!(read(&path)?, Some(END));
    assert_eq!(fs::read_dir(dir.path())?.count(), 1);
    Ok(())
}


#[test]
fn a_missing_file_is_none_and_anything_else_is_named() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("retro.state");
    assert!(read(&path)?.is_none());
    fs::write(&path, "")?;
    assert!(matches!(read(&path), Err(StateError::Format)));
    fs::write(&path, "1793707200")?;
    assert!(matches!(read(&path), Err(StateError::Format)));
    fs::write(&path, "-x 1793707200")?;
    assert!(matches!(read(&path), Err(StateError::Format)));
    fs::write(&path, b"tenant-\xff 1793707200")?;
    assert!(matches!(read(&path), Err(StateError::Format)));
    fs::write(&path, "tenant-a ")?;
    assert!(matches!(read(&path), Err(StateError::NotDigits)));
    fs::write(&path, "tenant-a 17937072ab")?;
    assert!(matches!(read(&path), Err(StateError::NotDigits)));
    fs::write(&path, "tenant-a 1793707200\n")?;
    assert!(matches!(read(&path), Err(StateError::NotDigits)));
    fs::write(&path, "tenant-a -1")?;
    assert!(matches!(read(&path), Err(StateError::NotDigits)));
    fs::write(&path, "tenant-a 99999999999999999999")?;
    assert!(matches!(read(&path), Err(StateError::Range)));
    fs::write(&path, "tenant-a 9223372036854775807")?;
    assert!(matches!(read(&path), Err(StateError::Range)));
    fs::write(&path, "tenant-a 0")?;
    assert_eq!(read(&path)?, Some(OffsetDateTime::UNIX_EPOCH));
    fs::write(&path, "1".repeat(MAX_STATE_BYTES as usize + 1))?;
    assert!(matches!(read(&path), Err(StateError::Read(_))));
    fs::write(&path, "1".repeat(ONE_MEGABYTE))?;
    assert!(matches!(read(&path), Err(StateError::Read(_))));
    assert!(matches!(read(&path.join("inner")), Err(StateError::Open(_))));
    fs::remove_file(&path)?;
    fs::create_dir(&path)?;
    assert!(matches!(read(&path), Err(StateError::Open(SecretFileError::NotRegular { .. }))));
    Ok(())
}


#[test]
fn a_future_end_is_ahead_and_a_small_skew_is_resumed() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("retro.state");
    fs::write(&path, FORGED)?;
    assert!(matches!(read(&path), Err(StateError::Ahead)));
    fs::write(&path, SKEW_EDGE)?;
    assert_eq!(read(&path)?.map(|end| end.unix_timestamp()), Some(SKEW_EDGE_SECONDS));
    fs::write(&path, PAST_SKEW_EDGE)?;
    assert!(matches!(read(&path), Err(StateError::Ahead)));
    Ok(())
}


#[test]
fn a_file_of_another_tenant_is_named() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("retro.state");
    fs::write(&path, "tenant-b 1793707200")?;
    assert!(matches!(read(&path), Err(StateError::OtherTenant)));
    Ok(())
}


#[test]
fn a_symlinked_state_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let victim = dir.path().join("victim");
    fs::write(&victim, END_TEXT)?;
    let path = dir.path().join("retro.state");
    symlink(&victim, &path)?;
    assert!(matches!(read(&path), Err(StateError::Open(SecretFileError::Symlink { .. }))));
    Ok(())
}


#[test]
fn a_failing_inspection_of_the_handle_is_an_open_error() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("retro.state");
    fs::write(&path, END_TEXT)?;
    assert!(matches!(open_state_with(&path, failing_inspection), Err(SecretFileError::Io { .. })));
    Ok(())
}


#[test]
fn a_planted_temporary_is_never_followed_or_reused() -> TestResult {
    let dir = tempdir()?;
    let victim = dir.path().join("victim");
    fs::write(&victim, "precious")?;
    let linked = dir.path().join("linked.tmp");
    symlink(&victim, &linked)?;
    let regular = dir.path().join("regular.tmp");
    fs::write(&regular, "planted")?;
    assert_eq!(
        temporary_options().open(&linked).err().map(|error| error.kind()),
        Some(ErrorKind::AlreadyExists)
    );
    assert_eq!(
        temporary_options().open(&regular).err().map(|error| error.kind()),
        Some(ErrorKind::AlreadyExists)
    );
    assert_eq!(fs::read_to_string(&victim)?, "precious");
    assert_eq!(fs::read_to_string(&regular)?, "planted");
    let path = dir.path().join("retro.state");
    write_end(&path, TENANT, END)?;
    assert_eq!(read(&path)?, Some(END));
    Ok(())
}


#[test]
fn a_failed_write_is_an_error_and_leaves_the_old_file() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("retro.state");
    write_end(&path, TENANT, END)?;
    assert_eq!(
        write_end(&path, TENANT, BEFORE_EPOCH).err().map(|error| error.kind()),
        Some(ErrorKind::InvalidInput)
    );
    assert_eq!(fs::read_to_string(&path)?, END_TEXT);
    let missing = dir.path().join("absent").join("retro.state");
    assert!(write_end(&missing, TENANT, END).is_err());
    let target = dir.path().join("directory");
    fs::create_dir(&target)?;
    assert!(write_end(&target, TENANT, END).is_err());
    assert_eq!(
        write_end(Path::new("/"), TENANT, END).err().map(|error| error.kind()),
        Some(ErrorKind::InvalidInput)
    );
    Ok(())
}


#[test]
fn the_start_names_what_the_first_round_starts_from() -> TestResult {
    assert_eq!(start_of(Ok(Some(END))), (Some(END), RESUMED));
    assert_eq!(start_of(Ok(None)), (None, NO_PREVIOUS_RUN));
    assert_eq!(start_of(Err(StateError::NotDigits)), (None, STATE_UNREADABLE));
    assert_eq!(start_of(Err(StateError::Ahead)), (None, STATE_AHEAD));
    assert_eq!(start_of(Err(StateError::OtherTenant)), (None, STATE_OTHER_TENANT));
    Ok(())
}


fn failing_removal(_path: &Path) -> io::Result<()> {
    Err(io::Error::from(ErrorKind::PermissionDenied))
}


fn leftovers(dir: &Path) -> Result<usize, io::Error> {
    Ok(fs::read_dir(dir)?.count())
}


#[test]
fn a_hard_linked_state_file_is_refused() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("retro.state");
    write_end(&path, TENANT, END)?;
    assert_eq!(read(&path)?, Some(END));
    fs::hard_link(&path, dir.path().join("other.link"))?;
    assert!(matches!(read(&path), Err(StateError::Open(SecretFileError::NotRegular { .. }))));
    Ok(())
}


#[test]
fn a_failed_rename_removes_its_temporary_and_a_failed_removal_is_survived() -> TestResult {
    let dir = tempdir()?;
    let target = dir.path().join("directory");
    fs::create_dir(&target)?;
    let before = leftovers(dir.path())?;
    assert!(write_end(&target, TENANT, END).is_err());
    assert_eq!(leftovers(dir.path())?, before);
    assert!(write_end_with(&target, TENANT, END, failing_removal).is_err());
    assert_eq!(leftovers(dir.path())?, before + 1);
    Ok(())
}


#[test]
fn a_clock_at_the_end_of_time_is_a_range_refusal() -> TestResult {
    assert!(matches!(read_end_at(END_OF_TIME)?, Err(StateError::Range)));
    Ok(())
}


fn read_end_at(now: OffsetDateTime) -> Result<Result<Option<OffsetDateTime>, StateError>, io::Error> {
    let dir = tempdir()?;
    let path = dir.path().join("retro.state");
    write_end(&path, TENANT, END)?;
    Ok(read_end(&path, TENANT, now))
}
