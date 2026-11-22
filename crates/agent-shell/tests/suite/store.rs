use crate::support::{owner_of, private_tempdir, write_private, NOW};
use crate::types::TestResult;
use agent_command::model::{CLOCK_SKEW_SECONDS, MAX_SESSION_ID_BYTES};
use agent_shell::error::StoreError;
use agent_shell::model::{StoreEntry, MAX_SHELL_SESSION_IDS, MAX_STORE_BYTES, STORE_FILE_NAME};
use agent_shell::store::{check_directory, judge_handle, judge_handle_with, parse_entries, read_capped, read_entries, record_session, write_entries};
use std::fs::{self, File};
use std::path::Path;


const INVALID_UTF8: u8 = 0xff;


const EXPIRES: u64 = NOW + 300;


const MODE_BITS: u32 = 0o777;


const PRIVATE_FILE: u32 = 0o600;


const FUTURE: u64 = NOW + 10_000;


const WORLD_READABLE: u32 = 0o644;


const OPEN_DIRECTORY: u32 = 0o755;


const PRIVATE_DIRECTORY: u32 = 0o700;


const DECIMAL_DIGITS: usize = 20;


fn store_path(directory: &Path) -> std::path::PathBuf {
    directory.join(STORE_FILE_NAME)
}


fn record(directory: &Path, session: &str, now: u64) -> Result<(), StoreError> {
    let owner = owner_of(directory).map_err(|_unreadable| StoreError::Replayed)?;
    record_session(directory, owner, session, EXPIRES, now)
}


fn stored_ids(directory: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let owner = owner_of(directory)?;
    Ok(read_entries(&store_path(directory), owner)?
        .into_iter()
        .map(|entry| entry.session_id)
        .collect())
}


#[test]
fn the_store_bound_holds_every_live_line() -> TestResult {
    let line = MAX_SESSION_ID_BYTES + 1 + DECIMAL_DIGITS + 1;
    assert!(u64::try_from(MAX_SHELL_SESSION_IDS * line).is_ok_and(|largest| largest <= MAX_STORE_BYTES));
    Ok(())
}


#[test]
fn an_id_is_recorded_once_and_a_replay_is_refused() -> TestResult {
    let directory = private_tempdir()?;
    record(directory.path(), "session-1", NOW)?;
    assert!(matches!(record(directory.path(), "session-1", NOW), Err(StoreError::Replayed)));
    record(directory.path(), "session-2", NOW)?;
    assert_eq!(stored_ids(directory.path())?, vec!["session-1".to_owned(), "session-2".to_owned()]);
    Ok(())
}


#[test]
fn a_restart_still_refuses_the_replayed_id() -> TestResult {
    let directory = private_tempdir()?;
    record(directory.path(), "session-1", NOW)?;
    assert!(matches!(record(directory.path(), "session-1", NOW + 1), Err(StoreError::Replayed)));
    Ok(())
}


#[test]
fn an_entry_is_pruned_once_its_expiry_and_the_skew_have_passed() -> TestResult {
    let directory = private_tempdir()?;
    record(directory.path(), "session-1", NOW)?;
    let last_live = EXPIRES + CLOCK_SKEW_SECONDS;
    assert!(matches!(record(directory.path(), "session-1", last_live), Err(StoreError::Replayed)));
    record(directory.path(), "session-2", last_live + 1)?;
    assert_eq!(stored_ids(directory.path())?, vec!["session-2".to_owned()]);
    Ok(())
}


fn fill(directory: &Path, count: usize, expires_at: u64) -> TestResult {
    let entries: Vec<StoreEntry> = (0..count)
        .map(|index| StoreEntry {
            session_id: format!("old-{index}"),
            expires_at,
        })
        .collect();
    write_entries(&store_path(directory), &entries)?;
    Ok(())
}


#[test]
fn a_full_live_window_refuses_and_an_expired_one_does_not() -> TestResult {
    let directory = private_tempdir()?;
    fill(directory.path(), MAX_SHELL_SESSION_IDS, FUTURE)?;
    assert!(matches!(record(directory.path(), "session-1", NOW), Err(StoreError::Full)));
    assert_eq!(stored_ids(directory.path())?.len(), MAX_SHELL_SESSION_IDS);
    fill(directory.path(), MAX_SHELL_SESSION_IDS, NOW)?;
    record(directory.path(), "session-1", FUTURE)?;
    assert_eq!(stored_ids(directory.path())?, vec!["session-1".to_owned()]);
    Ok(())
}


#[test]
fn the_store_file_is_private_and_missing_means_empty() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let directory = private_tempdir()?;
    assert!(stored_ids(directory.path())?.is_empty());
    record(directory.path(), "session-1", NOW)?;
    assert_eq!(fs::metadata(store_path(directory.path()))?.permissions().mode() & MODE_BITS, PRIVATE_FILE);
    Ok(())
}


#[test]
fn a_store_that_cannot_be_written_is_an_error() -> TestResult {
    let directory = private_tempdir()?;
    let missing = directory.path().join("missing").join(STORE_FILE_NAME);
    assert!(matches!(write_entries(&missing, &[]), Err(StoreError::Io { .. })));
    Ok(())
}


#[test]
fn a_symlinked_store_file_is_refused() -> TestResult {
    let directory = private_tempdir()?;
    let elsewhere = private_tempdir()?;
    let target = elsewhere.path().join("target");
    fs::write(&target, "session-1 1\n")?;
    std::os::unix::fs::symlink(&target, store_path(directory.path()))?;
    assert!(matches!(record(directory.path(), "session-9", NOW), Err(StoreError::Io { .. })));
    Ok(())
}


#[test]
fn a_fifo_store_file_is_refused_without_blocking() -> TestResult {
    let directory = private_tempdir()?;
    let made = std::process::Command::new("mkfifo").arg(store_path(directory.path())).status()?;
    assert!(made.success());
    assert!(matches!(record(directory.path(), "session-1", NOW), Err(StoreError::NotRegular { .. })));
    Ok(())
}


#[test]
fn a_store_file_of_another_owner_is_refused() -> TestResult {
    let directory = private_tempdir()?;
    record(directory.path(), "session-1", NOW)?;
    let owner = owner_of(directory.path())?;
    let refused = record_session(directory.path(), owner + 1, "session-2", EXPIRES, NOW);
    assert!(matches!(refused, Err(StoreError::Owner { .. })));
    Ok(())
}


#[test]
fn a_store_file_open_to_group_or_other_is_refused() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let directory = private_tempdir()?;
    record(directory.path(), "session-1", NOW)?;
    fs::set_permissions(store_path(directory.path()), fs::Permissions::from_mode(WORLD_READABLE))?;
    assert!(matches!(record(directory.path(), "session-2", NOW), Err(StoreError::Insecure { .. })));
    Ok(())
}


#[test]
fn a_directory_open_to_group_or_other_is_refused() -> TestResult {
    use std::os::unix::fs::PermissionsExt;
    let directory = private_tempdir()?;
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    assert!(matches!(record(directory.path(), "session-1", NOW), Err(StoreError::Insecure { .. })));
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(PRIVATE_DIRECTORY))?;
    record(directory.path(), "session-1", NOW)?;
    Ok(())
}


#[test]
fn a_directory_of_another_owner_is_refused() -> TestResult {
    let directory = private_tempdir()?;
    let owner = owner_of(directory.path())?;
    assert!(matches!(check_directory(directory.path(), owner + 1), Err(StoreError::Owner { .. })));
    Ok(())
}


#[test]
fn a_missing_symlinked_or_file_directory_is_refused() -> TestResult {
    let directory = private_tempdir()?;
    let owner = owner_of(directory.path())?;
    assert!(matches!(
        check_directory(&directory.path().join("missing"), owner),
        Err(StoreError::Io { .. })
    ));
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(directory.path(), &link)?;
    assert!(matches!(check_directory(&link, owner), Err(StoreError::Io { .. })));
    let plain = directory.path().join("plain");
    fs::write(&plain, "")?;
    assert!(matches!(check_directory(&plain, owner), Err(StoreError::Io { .. })));
    Ok(())
}


#[test]
fn a_handle_of_the_wrong_kind_is_named() -> TestResult {
    let directory = private_tempdir()?;
    let owner = owner_of(directory.path())?;
    let plain = directory.path().join("plain");
    fs::write(&plain, "")?;
    let file = File::open(&plain)?;
    assert!(matches!(judge_handle(&file, &plain, owner, true), Err(StoreError::NotDirectory { .. })));
    let handle = File::open(directory.path())?;
    assert!(matches!(
        judge_handle(&handle, directory.path(), owner, false),
        Err(StoreError::NotRegular { .. })
    ));
    Ok(())
}


fn corrupt_store(content: &[u8]) -> TestResult {
    let directory = private_tempdir()?;
    write_private(&store_path(directory.path()), content)?;
    let refused = record(directory.path(), "session-1", NOW);
    assert!(matches!(refused, Err(StoreError::Corrupt { .. })));
    Ok(())
}


#[test]
fn a_store_with_a_bad_line_is_refused_whole() -> TestResult {
    corrupt_store(b"session-1\n")?;
    corrupt_store(b"session-1 soon\n")?;
    corrupt_store(b"../x 5\n")?;
    corrupt_store(b"session-1 5\n\nsession-2 6\n")?;
    corrupt_store(&[INVALID_UTF8, INVALID_UTF8, b'\n'])?;
    Ok(())
}


#[test]
fn a_store_over_the_limit_is_refused_without_being_buffered() -> TestResult {
    let directory = private_tempdir()?;
    let oversized = usize::try_from(MAX_STORE_BYTES)? + 1;
    let path = store_path(directory.path());
    write_private(&path, &vec![b'a'; oversized])?;
    assert!(matches!(record(directory.path(), "session-1", NOW), Err(StoreError::TooLarge { .. })));
    let file = File::open(&path)?;
    assert!(matches!(read_capped(file, &path), Err(StoreError::TooLarge { .. })));
    Ok(())
}


#[test]
fn a_store_of_exactly_the_limit_is_read_not_refused_as_large() -> TestResult {
    let directory = private_tempdir()?;
    let full = usize::try_from(MAX_STORE_BYTES)?;
    write_private(&store_path(directory.path()), &vec![b'\n'; full])?;
    assert!(matches!(record(directory.path(), "session-1", NOW), Err(StoreError::Corrupt { .. })));
    assert!(parse_entries(Path::new("none"), Vec::new())?.is_empty());
    Ok(())
}


#[test]
fn a_handle_that_cannot_be_read_is_an_io_error() -> TestResult {
    let directory = private_tempdir()?;
    let handle = File::open(directory.path())?;
    assert!(matches!(read_capped(handle, directory.path()), Err(StoreError::Io { .. })));
    Ok(())
}


fn failing_inspection(_file: &File) -> std::io::Result<std::fs::Metadata> {
    Err(std::io::Error::other("fstat failed"))
}


#[test]
fn a_handle_that_cannot_be_inspected_is_an_io_error() -> TestResult {
    let directory = private_tempdir()?;
    let handle = File::open(directory.path())?;
    let refused = judge_handle_with(&handle, directory.path(), (owner_of(directory.path())?, true), failing_inspection);
    assert!(matches!(refused, Err(StoreError::Io { .. })));
    Ok(())
}
