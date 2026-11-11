use core_pg::error::PgError;
use core_pg::password::{read_capped, read_limited, read_password, read_secret, MAX_PASSWORD_BYTES, PASSWORD_CAPACITY};
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


#[test]
fn a_limit_of_u64_max_does_not_overflow() -> Result<(), Box<dyn std::error::Error>> {
    let kept: zeroize::Zeroizing<Vec<u8>> = read_capped(&mut "abc".as_bytes(), u64::MAX, "x")?;
    assert_eq!(kept.as_slice(), b"abc");
    Ok(())
}


const CHUNK: usize = 100;


const PROBE: usize = 32;


const CA_SIZE: usize = 5000;


const SCRATCH_LIMIT: u64 = 2048;


struct Recording {
    remaining: usize,
    calls: usize,
    addresses: Vec<(usize, usize, usize)>,
}


impl std::io::Read for Recording {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.calls += 1;
        let count = self.remaining.min(CHUNK).min(buf.len());
        self.addresses.push((buf.as_ptr() as usize, count, buf.len()));
        buf.iter_mut().take(count).for_each(|byte| *byte = b'k');
        self.remaining -= count;
        Ok(count)
    }
}


#[test]
fn a_secret_limit_at_or_above_the_capacity_is_refused_before_any_read() -> Result<(), Box<dyn Error>> {
    let capacity = u64::try_from(PASSWORD_CAPACITY)?;
    let limits = [capacity, capacity + 1, SCRATCH_LIMIT, u64::MAX];
    limits.iter().try_for_each(|limit| {
        let mut reader = Recording {
            remaining: CA_SIZE,
            calls: 0,
            addresses: Vec::new(),
        };
        let outcome = read_secret(&mut reader, *limit, "s");
        assert!(matches!(outcome, Err(PgError::SecretLimit { .. })));
        assert_eq!(reader.calls, 0);
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn a_secret_at_the_limit_is_read_and_one_byte_more_is_refused_without_reallocation() -> Result<(), Box<dyn Error>> {
    let exact: zeroize::Zeroizing<Vec<u8>> = read_secret(&mut vec![b'k'; usize::try_from(MAX_PASSWORD_BYTES)?].as_slice(), MAX_PASSWORD_BYTES, "s")?;
    assert_eq!(exact.capacity(), PASSWORD_CAPACITY);
    let mut reader = Recording {
        remaining: PASSWORD_CAPACITY,
        calls: 0,
        addresses: Vec::new(),
    };
    assert!(matches!(read_secret(&mut reader, MAX_PASSWORD_BYTES, "s"), Err(PgError::TooLarge { .. })));
    let first = reader.addresses.first().ok_or("no read")?.0;
    let mut offset = 0;
    reader.addresses.iter().filter(|entry| entry.2 > PROBE).for_each(|(address, count, _)| {
        assert_eq!(*address, first + offset);
        offset += count;
    });
    assert_eq!(reader.addresses.iter().map(|entry| entry.1).sum::<usize>(), PASSWORD_CAPACITY);
    assert!(offset >= PASSWORD_CAPACITY - PROBE);
    Ok(())
}


#[test]
fn a_ca_larger_than_the_password_capacity_is_still_read() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("ca");
    fs::write(&path, vec![b'c'; CA_SIZE])?;
    assert_eq!(read_limited(&path, u64::try_from(CA_SIZE)?)?.len(), CA_SIZE);
    Ok(())
}
