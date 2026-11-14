use crate::common::types::TestResult;
use crate::common::{
    claims, setup, token_for, FOURTH_LINE, GARBAGE_BYTE, LIFETIME, LINE_COUNT, NOW, PEER, RELAY_SEED, SECOND_NONCE, SEED_LENGTH, TENANT, THIRD_LINE,
};
use data_encoding::HEXLOWER;
use remote_desktop::cli::{
    check_owner_and_mode, line_verdict, read_line, read_signing_key, signing_key_from, verify_session, write_hex_line, write_issued,
    write_keypair_files, write_seed_file_checked, LINE_LIMIT,
};
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


#[cfg(unix)]
const MODE_BITS: u32 = 0o777;


const OWNER_ONLY: u32 = 0o600;


const GROUP_READABLE: u32 = 0o640;


const WORLD_READABLE: u32 = 0o644;


const OTHER_USER: u32 = 4242;


const ROOT_USER: u32 = 0;


const OVERSIZE_SEED_FILE: usize = 200;


#[cfg(unix)]
fn set_mode(path: &std::path::Path, mode: u32) -> io::Result<()> {
    std::fs::set_permissions(path, std::os::unix::fs::PermissionsExt::from_mode(mode))
}


#[cfg(not(unix))]
fn set_mode(_path: &std::path::Path, _mode: u32) -> io::Result<()> {
    Ok(())
}


fn seed_file(dir: &tempfile::TempDir, name: &str, text: &str, mode: u32) -> Result<String, Box<dyn std::error::Error>> {
    let path = dir.path().join(name);
    std::fs::write(&path, text)?;
    set_mode(&path, mode)?;
    Ok(path.display().to_string())
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
fn the_seed_is_read_from_a_private_file_and_never_from_the_command_line() -> TestResult {
    let dir = tempfile::tempdir()?;
    let hex = HEXLOWER.encode(&[RELAY_SEED; SEED_LENGTH]);
    let private = seed_file(&dir, "private", &format!("{hex}\n"), OWNER_ONLY)?;
    assert_eq!(
        read_signing_key(std::path::Path::new(&private))?.to_bytes(),
        signing_key_from(&hex)?.to_bytes()
    );
    let mut out = Vec::new();
    let refused = write_issued(&[&hex, &json(LIFETIME, "alice")], NOW, os_random, &mut out)
        .err()
        .ok_or("accepted")?;
    assert!(matches!(refused, CliError::SeedFile));
    assert!(!refused.to_string().contains(&hex));
    assert!(!format!("{refused:?}").contains(&hex));
    assert!(out.is_empty());
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_seed_file_open_to_group_or_other_is_refused_before_it_is_read() -> TestResult {
    let dir = tempfile::tempdir()?;
    let hex = HEXLOWER.encode(&[RELAY_SEED; SEED_LENGTH]);
    [WORLD_READABLE, GROUP_READABLE].iter().try_for_each(|mode| {
        let path = seed_file(&dir, "open", &hex, *mode)?;
        assert!(matches!(read_signing_key(std::path::Path::new(&path)), Err(CliError::SeedMode)));
        let mut out = Vec::new();
        assert!(matches!(
            write_issued(&[&path, &json(LIFETIME, "alice")], NOW, os_random, &mut out),
            Err(CliError::SeedMode)
        ));
        assert!(out.is_empty());
        Ok::<(), Box<dyn std::error::Error>>(())
    })
}


#[test]
fn the_owner_check_names_a_seed_file_of_another_user() -> TestResult {
    assert!(matches!(
        check_owner_and_mode(OWNER_ONLY, OTHER_USER, ROOT_USER),
        Err(CliError::SeedOwner)
    ));
    assert!(check_owner_and_mode(OWNER_ONLY, ROOT_USER, ROOT_USER).is_ok());
    assert!(matches!(
        check_owner_and_mode(WORLD_READABLE, ROOT_USER, ROOT_USER),
        Err(CliError::SeedMode)
    ));
    assert!(matches!(
        check_owner_and_mode(GROUP_READABLE, ROOT_USER, ROOT_USER),
        Err(CliError::SeedMode)
    ));
    Ok(())
}


#[test]
fn a_bad_seed_file_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("missing");
    assert!(matches!(read_signing_key(&missing), Err(CliError::SeedFile)));
    assert!(matches!(read_signing_key(dir.path()), Err(CliError::SeedFile)));
    let binary = dir.path().join("binary");
    std::fs::write(&binary, [GARBAGE_BYTE, GARBAGE_BYTE - 1])?;
    set_mode(&binary, OWNER_ONLY)?;
    assert!(matches!(read_signing_key(&binary), Err(CliError::SeedText)));
    let large = seed_file(&dir, "large", &"a".repeat(OVERSIZE_SEED_FILE), OWNER_ONLY)?;
    assert!(matches!(read_signing_key(std::path::Path::new(&large)), Err(CliError::SeedFile)));
    let short = seed_file(&dir, "short", "abcd", OWNER_ONLY)?;
    assert!(matches!(read_signing_key(std::path::Path::new(&short)), Err(CliError::Seed)));
    Ok(())
}


fn fixed_seed_hex() -> String {
    let fill: Vec<u8> = (0..SEED_LENGTH).map(|index| index as u8).collect();
    HEXLOWER.encode(&fill)
}


#[cfg(unix)]
fn mode_of(path: &std::path::Path) -> Result<u32, Box<dyn std::error::Error>> {
    Ok(std::os::unix::fs::PermissionsExt::mode(&std::fs::metadata(path)?.permissions()) & MODE_BITS)
}


#[cfg(unix)]
#[test]
fn keygen_creates_a_private_seed_file_and_a_public_file() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (seed_path, public_path) = (dir.path().join("seed"), dir.path().join("public"));
    let mut out = Vec::new();
    write_keypair_files(fixed_fill, &seed_path, &public_path, &mut out)?;
    let seed_text = std::fs::read_to_string(&seed_path)?;
    assert_eq!(seed_text, format!("{}\n", fixed_seed_hex()));
    assert_eq!(mode_of(&seed_path)?, OWNER_ONLY);
    assert_eq!(mode_of(&public_path)?, WORLD_READABLE);
    let expected_public = HEXLOWER.encode(&signing_key_from(&fixed_seed_hex())?.verifying_key().to_bytes());
    assert_eq!(std::fs::read_to_string(&public_path)?, format!("{expected_public}\n"));
    assert_eq!(String::from_utf8(out)?, format!("public {expected_public}\n"));
    assert_eq!(read_signing_key(&seed_path)?.to_bytes(), signing_key_from(&fixed_seed_hex())?.to_bytes());
    Ok(())
}


#[test]
fn keygen_never_prints_the_seed() -> TestResult {
    let dir = tempfile::tempdir()?;
    let mut out = Vec::new();
    write_keypair_files(fixed_fill, &dir.path().join("seed"), &dir.path().join("public"), &mut out)?;
    assert!(!String::from_utf8(out)?.contains(&fixed_seed_hex()));
    Ok(())
}


#[test]
fn keygen_refuses_an_existing_seed_path_and_leaves_it_unchanged() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (seed_path, public_path) = (dir.path().join("seed"), dir.path().join("public"));
    std::fs::write(&seed_path, "keep")?;
    let refusal = write_keypair_files(fixed_fill, &seed_path, &public_path, &mut Vec::new());
    assert!(matches!(refusal, Err(CliError::PublicKept(_))));
    assert_eq!(std::fs::read_to_string(&seed_path)?, "keep");
    let expected_public = HEXLOWER.encode(&signing_key_from(&fixed_seed_hex())?.verifying_key().to_bytes());
    assert_eq!(std::fs::read_to_string(&public_path)?, format!("{expected_public}\n"));
    Ok(())
}


#[test]
fn keygen_refuses_an_existing_public_path_and_never_creates_the_seed() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (seed_path, public_path) = (dir.path().join("seed"), dir.path().join("public"));
    std::fs::write(&public_path, "keep")?;
    let mut out = Vec::new();
    assert!(matches!(
        write_keypair_files(fixed_fill, &seed_path, &public_path, &mut out),
        Err(CliError::Io(_))
    ));
    assert!(matches!(std::fs::symlink_metadata(&seed_path), Err(error) if error.kind() == io::ErrorKind::NotFound));
    assert_eq!(std::fs::read_to_string(&public_path)?, "keep");
    assert!(out.is_empty());
    Ok(())
}


#[cfg(unix)]
#[test]
fn keygen_does_not_follow_a_symlink_at_the_seed_path() -> TestResult {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("target");
    let seed_path = dir.path().join("seed");
    std::os::unix::fs::symlink(&target, &seed_path)?;
    let refusal = write_keypair_files(fixed_fill, &seed_path, &dir.path().join("public"), &mut Vec::new());
    assert!(matches!(refusal, Err(CliError::PublicKept(_))));
    assert!(!target.exists());
    Ok(())
}


#[test]
fn a_failing_draw_writes_nothing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (seed_path, public_path) = (dir.path().join("seed"), dir.path().join("public"));
    assert!(matches!(
        write_keypair_files(failing_fill, &seed_path, &public_path, &mut Vec::new()),
        Err(CliError::Random(_))
    ));
    assert!(!seed_path.exists() && !public_path.exists());
    Ok(())
}


#[test]
fn a_missing_seed_directory_keeps_the_public_file_and_names_its_kind() -> TestResult {
    let dir = tempfile::tempdir()?;
    let public_path = dir.path().join("public");
    let missing = dir.path().join("missing").join("seed");
    let refusal = write_keypair_files(fixed_fill, &missing, &public_path, &mut Vec::new())
        .err()
        .ok_or("accepted")?;
    assert!(matches!(refusal, CliError::PublicKept(_)));
    assert!(!refusal.to_string().contains(&*dir.path().to_string_lossy()));
    assert!(public_path.exists());
    Ok(())
}


fn refusing_check(_file: &std::fs::File) -> Result<(), CliError> {
    Err(CliError::SeedMode)
}


#[test]
fn a_refused_seed_handle_gets_no_byte_and_nothing_is_removed() -> TestResult {
    let dir = tempfile::tempdir()?;
    let seed_path = dir.path().join("seed");
    let refusal = write_seed_file_checked(&seed_path, fixed_seed_hex().as_bytes(), refusing_check)
        .err()
        .ok_or("accepted")?;
    assert!(matches!(refusal, CliError::SeedMode));
    assert_eq!(std::fs::metadata(&seed_path)?.len(), 0);
    Ok(())
}


#[cfg(unix)]
#[test]
fn the_handle_check_refuses_a_lax_mode_and_accepts_a_private_file() -> TestResult {
    use remote_desktop::cli::check_seed_handle;
    let dir = tempfile::tempdir()?;
    let lax_path = dir.path().join("lax");
    let lax = std::fs::File::create(&lax_path)?;
    set_mode(&lax_path, WORLD_READABLE)?;
    assert!(matches!(check_seed_handle(&lax), Err(CliError::SeedMode)));
    let private_path = dir.path().join("private");
    let private = std::fs::File::create(&private_path)?;
    set_mode(&private_path, OWNER_ONLY)?;
    check_seed_handle(&private)?;
    Ok(())
}


#[test]
fn a_failing_stdout_leaves_both_files() -> TestResult {
    let dir = tempfile::tempdir()?;
    let (seed_path, public_path) = (dir.path().join("seed"), dir.path().join("public"));
    assert!(matches!(
        write_keypair_files(fixed_fill, &seed_path, &public_path, &mut FailingWriter),
        Err(CliError::Io(_))
    ));
    assert!(seed_path.exists() && public_path.exists());
    Ok(())
}


#[test]
fn a_failed_write_is_reported() -> TestResult {
    assert!(matches!(write_hex_line(&mut FailingWriter, b"ab"), Err(CliError::Io(_))));
    Ok(())
}


#[test]
fn the_signing_key_comes_from_a_32_byte_hex_seed() -> TestResult {
    assert!(signing_key_from(&HEXLOWER.encode(&[RELAY_SEED; SEED_LENGTH])).is_ok());
    assert!(matches!(signing_key_from("abcd"), Err(CliError::Seed)));
    let wrong_length = signing_key_from("abcdef0123").err().ok_or("accepted")?;
    assert!(matches!(wrong_length, CliError::Seed));
    assert!(!wrong_length.to_string().contains("abcdef0123"));
    assert!(!format!("{wrong_length:?}").contains("abcdef0123"));
    assert!(matches!(signing_key_from("zz"), Err(CliError::Hex(_))));
    assert!(matches!(signing_key_from("abc"), Err(CliError::Hex(_))));
    let bad_last = format!("{}Z", "ab".repeat(SEED_LENGTH - 1) + "a");
    assert!(matches!(signing_key_from(&bad_last), Err(CliError::Hex(_))));
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
    let dir = tempfile::tempdir()?;
    let seed = seed_file(&dir, "seed", &HEXLOWER.encode(&[RELAY_SEED; SEED_LENGTH]), OWNER_ONLY)?;
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
    let dir = tempfile::tempdir()?;
    let seed = seed_file(&dir, "seed", &HEXLOWER.encode(&[RELAY_SEED; SEED_LENGTH]), OWNER_ONLY)?;
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
        write_issued(&[&seed_file(&dir, "bad", "zz", OWNER_ONLY)?, &valid], NOW, os_random, &mut Vec::new()),
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
