use crate::common::types::TestResult;
use crate::common::{
    claims, setup, token_for, FOURTH_LINE, GARBAGE_BYTE, LIFETIME, LINE_COUNT, NOW, PEER, RELAY_SEED, SECOND_NONCE, SEED_LENGTH, TENANT, THIRD_LINE,
};
use data_encoding::HEXLOWER;
use remote_desktop::cli::{line_verdict, read_line, signing_key_from, verify_session, write_issued, write_keypair, LINE_LIMIT};
use remote_desktop::error::CliError;
use remote_desktop::model::{Line, MAX_TOKEN_BYTES};
use remote_desktop::sign::{new_identifiers, os_random};
use std::io::{self, BufRead, BufReader, Cursor, Read, Write};


const TEN_MEBIBYTES: usize = 10 * 1024 * 1024;


const SMALL_CHUNK: usize = 16;


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("closed"))
    }
}


struct FlushFails;


impl Write for FlushFails {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("flush closed"))
    }
}


struct SecondWriteFails {
    writes: usize,
}


impl Write for SecondWriteFails {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.writes += 1;
        if self.writes > 1 && buffer.contains(&b'\n') {
            Err(io::Error::other("closed"))
        } else {
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


struct ServesThenFails {
    remaining: usize,
}


impl Read for ServesThenFails {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if self.remaining == 0 {
            Err(io::Error::other("reset"))
        } else {
            let served = buffer.len().min(self.remaining);
            buffer.iter_mut().take(served).for_each(|byte| *byte = b'a');
            self.remaining -= served;
            Ok(served)
        }
    }
}


fn failing_fill(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


fn fixed_fill(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    buffer.iter_mut().enumerate().for_each(|(index, byte)| *byte = index as u8);
    Ok(())
}


fn clock() -> u64 {
    NOW
}


fn run(input: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
    let setup = setup()?;
    let mut out = Vec::new();
    verify_session(
        &setup.verifier,
        BufReader::with_capacity(SMALL_CHUNK, input),
        &mut out,
        clock,
        PEER,
        TENANT,
    )?;
    Ok(String::from_utf8(out)?)
}


fn json(lifetime: u64, subject: &str) -> String {
    format!("{{\"key_id\":\"relay-1\",\"tenant\":\"{TENANT}\",\"device_peer_id\":\"{PEER}\",\"viewer_subject\":\"{subject}\",\"lifetime_seconds\":{lifetime}}}")
}


#[test]
fn keygen_writes_a_seed_and_its_public_key() -> TestResult {
    let mut out = Vec::new();
    write_keypair(fixed_fill, &mut out)?;
    let text = String::from_utf8(out)?;
    let seed = text.lines().next().and_then(|line| line.strip_prefix("seed ")).ok_or("no seed")?;
    assert_eq!(HEXLOWER.decode(seed.as_bytes())?.len(), SEED_LENGTH);
    assert!(text.lines().nth(1).ok_or("no public")?.starts_with("public "));
    assert!(matches!(write_keypair(failing_fill, &mut Vec::new()), Err(CliError::Random(_))));
    assert!(matches!(write_keypair(fixed_fill, &mut FailingWriter), Err(CliError::Io(_))));
    assert!(matches!(
        write_keypair(fixed_fill, &mut SecondWriteFails { writes: 0 }),
        Err(CliError::Io(_))
    ));
    Ok(())
}


#[test]
fn the_signing_key_comes_from_a_32_byte_hex_seed() -> TestResult {
    assert!(signing_key_from(&HEXLOWER.encode(&[RELAY_SEED; SEED_LENGTH])).is_ok());
    assert!(matches!(signing_key_from("abcd"), Err(CliError::Seed)));
    assert!(matches!(signing_key_from("zz"), Err(CliError::Hex(_))));
    Ok(())
}


#[test]
fn identifiers_come_from_one_draw_and_a_failed_draw_is_reported() -> TestResult {
    let (session_id, nonce) = new_identifiers(fixed_fill)?;
    assert_eq!(session_id.first(), Some(&0));
    assert_eq!(nonce.first(), Some(&(session_id.len() as u8)));
    assert!(new_identifiers(failing_fill).is_err());
    assert!(new_identifiers(os_random).is_ok());
    Ok(())
}


#[test]
fn an_issued_token_is_verified_by_the_session() -> TestResult {
    let seed = HEXLOWER.encode(&[RELAY_SEED; SEED_LENGTH]);
    let mut out = Vec::new();
    write_issued(&[&seed, &json(LIFETIME, "alice")], NOW, os_random, &mut out)?;
    let token = String::from_utf8(out)?;
    let verdicts = run(format!("{token}{token}").as_bytes())?;
    let lines: Vec<&str> = verdicts.lines().collect();
    assert!(lines.first().ok_or("no verdict")?.starts_with("accepted "));
    assert_eq!(lines.get(1), Some(&"refused token was already used"));
    Ok(())
}


#[test]
fn issuing_reports_its_failures() -> TestResult {
    let seed = HEXLOWER.encode(&[RELAY_SEED; SEED_LENGTH]);
    let valid = json(LIFETIME, "alice");
    assert!(matches!(write_issued(&[&seed], NOW, os_random, &mut Vec::new()), Err(CliError::Usage(_))));
    assert!(matches!(
        write_issued(&[&seed, "{"], NOW, os_random, &mut Vec::new()),
        Err(CliError::Request(_))
    ));
    let unknown = valid.replace("lifetime_seconds", "lifetime");
    assert!(matches!(
        write_issued(&[&seed, &unknown], NOW, os_random, &mut Vec::new()),
        Err(CliError::Request(_))
    ));
    assert!(matches!(
        write_issued(&[&seed, &valid], NOW, failing_fill, &mut Vec::new()),
        Err(CliError::Random(_))
    ));
    assert!(matches!(
        write_issued(&["zz", &valid], NOW, os_random, &mut Vec::new()),
        Err(CliError::Hex(_))
    ));
    let large = json(LIFETIME, &"a".repeat(MAX_TOKEN_BYTES));
    assert!(matches!(
        write_issued(&[&seed, &large], NOW, os_random, &mut Vec::new()),
        Err(CliError::Issue(_))
    ));
    assert!(matches!(
        write_issued(&[&seed, &valid], NOW, os_random, &mut FailingWriter),
        Err(CliError::Io(_))
    ));
    Ok(())
}


#[test]
fn the_session_reports_each_kind_of_line() -> TestResult {
    let good = token_for(&claims(1))?;
    let wrong_peer = token_for(&{
        let mut other = claims(SECOND_NONCE);
        other.device_peer_id = "1".to_owned();
        other
    })?;
    let input = format!("{good}\r\n{wrong_peer}\n\n{good}");
    let verdicts = run(input.as_bytes())?;
    let lines: Vec<&str> = verdicts.lines().collect();
    assert_eq!(lines.len(), LINE_COUNT);
    assert!(lines.first().ok_or("none")?.starts_with("accepted 01010101"));
    assert_eq!(lines.get(1), Some(&"refused token is for another device"));
    assert!(lines.get(THIRD_LINE).ok_or("none")?.starts_with("refused malformed token"));
    assert_eq!(lines.get(FOURTH_LINE), Some(&"refused token was already used"));
    assert_eq!(run(b"")?, "");
    Ok(())
}


#[test]
fn a_line_that_is_not_text_is_refused() -> TestResult {
    assert_eq!(run(&[GARBAGE_BYTE, GARBAGE_BYTE - 1, b'\n'])?, "refused token is not text\n");
    Ok(())
}


#[test]
fn a_ten_mebibyte_line_is_refused_without_being_buffered_and_the_next_line_is_served() -> TestResult {
    let good = token_for(&claims(1))?;
    let mut input = vec![b'a'; TEN_MEBIBYTES];
    input.push(b'\n');
    input.extend_from_slice(good.as_bytes());
    input.push(b'\n');
    let verdicts = run(&input)?;
    let lines: Vec<&str> = verdicts.lines().collect();
    assert_eq!(lines.first(), Some(&"refused token is too large"));
    assert!(lines.get(1).ok_or("none")?.starts_with("accepted "));
    let mut reader = Cursor::new(input);
    assert_eq!(read_line(&mut reader)?, Some(Line::TooLong));
    assert!(reader.fill_buf()?.starts_with(good.as_bytes()));
    Ok(())
}


#[test]
fn read_line_bounds_a_line_at_the_limit() -> TestResult {
    let mut exact = vec![b'a'; LINE_LIMIT - 1];
    exact.push(b'\n');
    assert_eq!(read_line(&mut Cursor::new(exact.clone()))?, Some(Line::Text(exact)));
    let unterminated = vec![b'a'; LINE_LIMIT - 1];
    assert_eq!(read_line(&mut Cursor::new(unterminated.clone()))?, Some(Line::Text(unterminated)));
    assert_eq!(read_line(&mut Cursor::new(vec![b'a'; LINE_LIMIT]))?, Some(Line::TooLong));
    assert_eq!(read_line(&mut Cursor::new(Vec::new()))?, None);
    Ok(())
}


#[test]
fn line_verdict_names_a_too_long_line() -> TestResult {
    let setup = setup()?;
    assert_eq!(
        line_verdict(&setup.verifier, &Line::TooLong, PEER, TENANT, NOW),
        "refused token is too large"
    );
    Ok(())
}


#[test]
fn io_failures_stop_the_session() -> TestResult {
    let setup = setup()?;
    let good = format!("{}\n", token_for(&claims(1))?);
    let write_fails = verify_session(&setup.verifier, good.as_bytes(), &mut FailingWriter, clock, PEER, TENANT);
    assert!(matches!(write_fails, Err(CliError::Io(_))));
    let flush_fails = verify_session(&setup.verifier, good.as_bytes(), &mut FlushFails, clock, PEER, TENANT);
    assert!(matches!(flush_fails, Err(CliError::Io(_))));
    [0, LINE_LIMIT].iter().try_for_each(|remaining| {
        let reader = BufReader::with_capacity(SMALL_CHUNK, ServesThenFails { remaining: *remaining });
        let reset = verify_session(&setup.verifier, reader, &mut Vec::new(), clock, PEER, TENANT);
        if matches!(reset, Err(CliError::Io(_))) {
            Ok(())
        } else {
            Err(format!("a reader failing after {remaining} bytes did not stop the session"))
        }
    })?;
    Ok(())
}
