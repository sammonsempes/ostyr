use core_pg::error::PgError;
use core_pg::password::{read_capped, read_limited, read_password, MAX_PASSWORD_BYTES};
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use tempfile::tempdir;


const ROOM: u64 = 8;


const TIGHT: u64 = 2;


const HUGE: usize = 2000;


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }
}


#[test]
fn trailing_line_breaks_are_trimmed() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("pass");
    fs::write(&path, "s3cret pass\r\n\n")?;
    assert_eq!(read_password(&path)?.as_slice(), b"s3cret pass");
    Ok(())
}


#[test]
fn password_at_the_cap_is_read_and_one_more_byte_is_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("pass");
    let at_cap = usize::try_from(MAX_PASSWORD_BYTES)?;
    fs::write(&path, "a".repeat(at_cap))?;
    assert_eq!(read_password(&path)?.len(), at_cap);
    fs::write(&path, "a".repeat(at_cap + 1))?;
    assert!(matches!(read_password(&path), Err(PgError::TooLarge { .. })));
    Ok(())
}


#[test]
fn empty_and_blank_passwords_are_refused() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("pass");
    fs::write(&path, "")?;
    assert!(matches!(read_password(&path), Err(PgError::EmptyPassword { .. })));
    fs::write(&path, "\n\n")?;
    assert!(matches!(read_password(&path), Err(PgError::EmptyPassword { .. })));
    Ok(())
}


#[test]
fn missing_file_and_failing_reader_are_io_errors() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    assert!(matches!(read_limited(&dir.path().join("absent"), 1), Err(PgError::Io { .. })));
    assert!(matches!(read_capped(&mut Failing, 1, "x"), Err(PgError::Io { .. })));
    let outcome: Result<zeroize::Zeroizing<Vec<u8>>, PgError> = read_capped(&mut Failing, 1, "x");
    assert!(outcome.is_err());
    Ok(())
}


#[test]
fn errors_never_hold_the_password() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("pass");
    fs::write(&path, "x".repeat(HUGE))?;
    let message = format!("{:?}", read_password(&path));
    assert!(!message.contains("xxxxxxxx"), "{message}");
    Ok(())
}


#[test]
fn the_capped_buffer_is_zeroizing_on_every_path() -> Result<(), Box<dyn Error>> {
    let kept: zeroize::Zeroizing<Vec<u8>> = read_capped(&mut "abc".as_bytes(), ROOM, "x")?;
    assert_eq!(kept.as_slice(), b"abc");
    assert!(matches!(read_capped(&mut "abcdef".as_bytes(), TIGHT, "x"), Err(PgError::TooLarge { .. })));
    Ok(())
}
