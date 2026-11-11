#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use core_pg::password::{read_secret, MAX_PASSWORD_BYTES, PASSWORD_CAPACITY};
use oncall::error::KeyError;
use oncall::limits::{MAX_LINK_KEY_BYTES, MIN_LINK_KEY_BYTES};
use oncall::linkkey::{check_owner_and_mode, key_from_bytes, mode_and_owners, read_link_key};
use std::error::Error;
use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use types::TestResult;
use zeroize::Zeroizing;


const PRIVATE_MODE: u32 = 0o600;


const GROUP_READABLE_MODE: u32 = 0o640;


const OTHER_USER: u32 = 4242;


fn key_file(directory: &Path, bytes: &[u8], mode: u32) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let path = directory.join("link.key");
    fs::write(&path, bytes)?;
    fs::set_permissions(&path, Permissions::from_mode(mode))?;
    Ok(path)
}


#[test]
fn a_private_key_file_of_the_right_size_is_read() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let bytes = vec![b'k'; MIN_LINK_KEY_BYTES];
    read_link_key(&key_file(directory.path(), &bytes, PRIVATE_MODE)?)?;
    assert!(key_from_bytes(Zeroizing::new(bytes.clone())).is_ok());
    let (mode, owner, process_user) = mode_and_owners(&fs::metadata(directory.path().join("link.key"))?)?;
    assert_eq!((mode & PRIVATE_MODE, owner), (PRIVATE_MODE, process_user));
    Ok(())
}


#[test]
fn a_file_open_to_group_is_refused() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let path = key_file(directory.path(), &[b'k'; MIN_LINK_KEY_BYTES], GROUP_READABLE_MODE)?;
    assert!(matches!(read_link_key(&path), Err(KeyError::Mode)));
    Ok(())
}


#[test]
fn another_owner_is_refused_on_the_given_identities() -> TestResult {
    assert!(matches!(check_owner_and_mode(PRIVATE_MODE, OTHER_USER, 0), Err(KeyError::Owner)));
    assert!(check_owner_and_mode(PRIVATE_MODE, OTHER_USER, OTHER_USER).is_ok());
    Ok(())
}


#[test]
fn a_fifo_a_directory_a_missing_file_and_an_oversized_file_are_refused() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let fifo = directory.path().join("pipe");
    assert!(std::process::Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(matches!(read_link_key(&fifo), Err(KeyError::File(_))));
    assert!(matches!(read_link_key(directory.path()), Err(KeyError::File(_))));
    assert!(matches!(read_link_key(&directory.path().join("absent")), Err(KeyError::File(_))));
    let big = vec![b'k'; usize::try_from(MAX_LINK_KEY_BYTES)? + 1];
    assert!(matches!(
        read_link_key(&key_file(directory.path(), &big, PRIVATE_MODE)?),
        Err(KeyError::File(_))
    ));
    Ok(())
}


#[test]
fn a_short_key_is_refused_and_the_limit_itself_is_accepted() -> TestResult {
    assert!(matches!(
        key_from_bytes(Zeroizing::new(vec![b'k'; MIN_LINK_KEY_BYTES - 1])),
        Err(KeyError::TooShort { min: MIN_LINK_KEY_BYTES })
    ));
    assert!(key_from_bytes(Zeroizing::new(vec![b'k'; MIN_LINK_KEY_BYTES])).is_ok());
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let at_limit = vec![b'k'; usize::try_from(MAX_LINK_KEY_BYTES)?];
    assert!(read_link_key(&key_file(directory.path(), &at_limit, PRIVATE_MODE)?).is_ok());
    Ok(())
}


#[test]
fn every_secret_limit_fits_the_preallocated_capacity() -> TestResult {
    let capacity = u64::try_from(PASSWORD_CAPACITY)?;
    assert!(MAX_PASSWORD_BYTES < capacity);
    assert!(MAX_LINK_KEY_BYTES < capacity);
    let kept: Zeroizing<Vec<u8>> = read_secret(&mut vec![b'k'; usize::try_from(MAX_LINK_KEY_BYTES)?].as_slice(), MAX_LINK_KEY_BYTES, "x")?;
    assert_eq!(kept.capacity(), PASSWORD_CAPACITY);
    Ok(())
}
