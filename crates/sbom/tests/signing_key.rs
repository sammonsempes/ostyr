#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use sbom::error::SigningError;
use sbom::signing::load_signing_key;
use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;
use types::TestResult;


const SEED_LENGTH: usize = 32;


const SEED: [u8; SEED_LENGTH] = [7; SEED_LENGTH];


const SMALL_LIMIT: usize = 4;


const PRIVATE_MODE: u32 = 0o600;


const OPEN_MODE: u32 = 0o644;


const DIRECTORY_MODE: u32 = 0o700;


const SEED_HEX: &str = "0707070707070707070707070707070707070707070707070707070707070707";


fn write_key(directory: &std::path::Path, text: &str, mode: u32) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = directory.join("sbom.key");
    let mut file = fs::File::create(&path)?;
    file.write_all(text.as_bytes())?;
    fs::set_permissions(&path, fs::Permissions::from_mode(mode))?;
    Ok(path)
}


#[test]
fn key_file_loads() -> TestResult {
    let directory = tempdir()?;
    let path = write_key(directory.path(), &format!("{SEED_HEX}\n"), PRIVATE_MODE)?;
    let key = load_signing_key(&path)?;
    assert_eq!(key.to_bytes(), SEED);
    Ok(())
}


#[test]
fn key_file_refusals_carry_no_key_material() -> TestResult {
    let directory = tempdir()?;
    let open = write_key(directory.path(), SEED_HEX, OPEN_MODE)?;
    let refused = load_signing_key(&open).err().ok_or("accepted")?;
    assert!(matches!(refused, SigningError::KeyNotPrivate(_)));
    assert!(!format!("{refused:?} {refused}").contains(SEED_HEX));
    let bad = write_key(directory.path(), &"zz".repeat(SEED_LENGTH), PRIVATE_MODE)?;
    assert!(matches!(load_signing_key(&bad), Err(SigningError::KeyHex(_))));
    let short = write_key(directory.path(), "0707", PRIVATE_MODE)?;
    assert!(matches!(load_signing_key(&short), Err(SigningError::KeyLength)));
    let long = write_key(directory.path(), &SEED_HEX.repeat(SMALL_LIMIT), PRIVATE_MODE)?;
    assert!(matches!(load_signing_key(&long), Err(SigningError::KeyTooLarge)));
    let padded = write_key(
        directory.path(),
        &format!("{SEED_HEX}{}garbage", " ".repeat(SEED_HEX.len())),
        PRIVATE_MODE,
    )?;
    assert!(matches!(load_signing_key(&padded), Err(SigningError::KeyTooLarge)));
    assert!(matches!(load_signing_key(&directory.path().join("missing")), Err(SigningError::KeyIo(_))));
    Ok(())
}


#[test]
fn key_file_read_failure_is_an_io_error() -> TestResult {
    let directory = tempdir()?;
    let private = directory.path().join("private");
    fs::create_dir(&private)?;
    fs::set_permissions(&private, fs::Permissions::from_mode(DIRECTORY_MODE))?;
    assert!(matches!(load_signing_key(&private), Err(SigningError::KeyNotRegular)));
    Ok(())
}


#[test]
fn key_fifo_is_refused_at_once() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("fifo.key");
    rustix::fs::mknodat(
        rustix::fs::CWD,
        &path,
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(PRIVATE_MODE),
        0,
    )?;
    assert!(matches!(load_signing_key(&path), Err(SigningError::KeyNotRegular)));
    Ok(())
}
