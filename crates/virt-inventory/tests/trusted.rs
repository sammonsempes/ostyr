#![cfg(unix)]


#[path = "common/types.rs"]
mod types;


use rustix::fs::{FileType, Mode, RawMode};
use std::error::Error;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use tempfile::tempdir;
use types::TestResult;
use virt_inventory::trusted::{file_trusted, read_trusted_text};


const REGULAR: RawMode = 0o100_644;


const GROUP_WRITABLE: RawMode = 0o100_664;


const OTHER_WRITABLE: RawMode = 0o100_646;


const DIRECTORY: RawMode = 0o040_755;


const SERVICE_USER: u32 = 1000;


const OTHER_USER: u32 = 2000;


const MAX: u64 = 64;


const OVER_MAX: usize = 100;


const OWNER_ONLY_FILE: RawMode = 0o100_600;


const FIFO_MODE: u32 = 0o600;


const WORLD_WRITABLE: u32 = 0o666;


const READABLE: u32 = 0o644;


const OPEN_DIRECTORY: u32 = 0o777;


const PRIVATE_DIRECTORY: u32 = 0o700;


const NOT_UTF8: [u8; 2] = [0xff, 0xfe];


#[test]
fn the_predicate_wants_a_regular_file_of_root_or_the_service_user_closed_to_group_and_other_writes() -> TestResult {
    assert!(file_trusted(REGULAR, SERVICE_USER, SERVICE_USER));
    assert!(file_trusted(REGULAR, 0, SERVICE_USER));
    assert!(file_trusted(OWNER_ONLY_FILE, SERVICE_USER, SERVICE_USER));
    assert!(!file_trusted(REGULAR, OTHER_USER, SERVICE_USER));
    assert!(!file_trusted(GROUP_WRITABLE, SERVICE_USER, SERVICE_USER));
    assert!(!file_trusted(OTHER_WRITABLE, 0, SERVICE_USER));
    assert!(!file_trusted(DIRECTORY, SERVICE_USER, SERVICE_USER));
    Ok(())
}


fn refusal_text(path: &Path) -> Result<String, Box<dyn Error>> {
    Ok(read_trusted_text(path, MAX).err().ok_or("expected a refusal")?.to_string())
}


#[test]
fn a_judged_file_is_read_and_every_other_form_is_refused_by_name() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("ca.pem");
    fs::write(&file, "PEM")?;
    assert_eq!(read_trusted_text(&file, MAX)?, "PEM");
    assert!(refusal_text(&dir.path().join("absent.pem"))?.contains("absent.pem"));
    symlink(&file, dir.path().join("link.pem"))?;
    assert!(refusal_text(&dir.path().join("link.pem"))?.contains("link.pem"));
    let fifo = dir.path().join("fifo.pem");
    rustix::fs::mknodat(rustix::fs::CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(FIFO_MODE), 0)?;
    assert!(refusal_text(&fifo)?.contains("fifo.pem"));
    fs::set_permissions(&file, fs::Permissions::from_mode(WORLD_WRITABLE))?;
    assert!(refusal_text(&file)?.contains("not a regular file of root"));
    fs::set_permissions(&file, fs::Permissions::from_mode(READABLE))?;
    fs::write(dir.path().join("big.pem"), vec![b'a'; OVER_MAX])?;
    assert!(refusal_text(&dir.path().join("big.pem"))?.contains("big.pem"));
    fs::write(dir.path().join("binary.pem"), NOT_UTF8)?;
    assert!(refusal_text(&dir.path().join("binary.pem"))?.contains("binary.pem"));
    assert!(refusal_text(Path::new("/"))?.contains("not trusted"));
    assert!(refusal_text(Path::new("relative.pem"))?.contains("not trusted"));
    Ok(())
}


#[test]
fn a_directory_that_others_can_write_is_refused_for_every_file_in_it() -> TestResult {
    let dir = tempdir()?;
    let file = dir.path().join("ca.pem");
    fs::write(&file, "PEM")?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(OPEN_DIRECTORY))?;
    let refused = refusal_text(&file);
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(PRIVATE_DIRECTORY))?;
    assert!(refused?.contains("not trusted"));
    Ok(())
}
