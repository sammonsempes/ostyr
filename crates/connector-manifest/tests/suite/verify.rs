use crate::common::types::TestResult;
use crate::common::{key_file_text, manifest_with, public_hex, signing_key, KEY_ID, NOT_AFTER, PUBLISHER, SEED_BYTE, VALID_MANIFEST};
use connector_manifest::cli::{epoch_seconds, run, USAGE};
use connector_manifest::error::ConnectorError;
use connector_manifest::keys::parse_trusted_keys;
use connector_manifest::model::{TrustedKeys, MANIFEST_NAME, MAX_KEY_FILE_BYTES, SIGNATURE_NAME};
use connector_manifest::package::read_package;
use connector_manifest::verify::{
    check_package, parse_signature_file, read_document, sign_directory, sign_package, signed_document, verify_package, write_signature, MAGIC_LINE,
};
use data_encoding::HEXLOWER;
use ed25519_dalek::{Signer, SECRET_KEY_LENGTH};
use std::fs::{self, Permissions};
use std::io::{self, Write};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tempfile::TempDir;


const NOW: u64 = 1_000;


const CODE: &[u8] = b"print(1)";


const OWNER_ONLY: u32 = 0o600;


const GROUP_READABLE: u32 = 0o640;


const NOT_UTF8: u8 = 0xff;


const TWO_FILES: usize = 2;


const FLIPPED_DIGIT: &str = "0";


fn trusted(not_after: u64) -> Result<TrustedKeys, Box<dyn std::error::Error>> {
    Ok(parse_trusted_keys(
        &key_file_text(KEY_ID, PUBLISHER, &public_hex(), not_after),
        "keys.yaml",
    )?)
}


fn put(directory: &Path, name: &str, bytes: &[u8]) -> TestResult {
    fs::write(directory.join(name), bytes)?;
    Ok(())
}


fn signed_dir() -> Result<TempDir, Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    put(directory.path(), MANIFEST_NAME, VALID_MANIFEST.as_bytes())?;
    put(directory.path(), "main.py", CODE)?;
    let text = sign_package(&read_package(directory.path())?, KEY_ID, &signing_key())?;
    write_signature(directory.path(), &text)?;
    Ok(directory)
}


fn verdict(directory: &Path) -> Result<ConnectorError, Box<dyn std::error::Error>> {
    match verify_package(directory, &trusted(NOT_AFTER)?, NOW) {
        Ok(_) => Err("package verified".into()),
        Err(error) => Ok(error),
    }
}


fn key_file(directory: &Path, mode: u32) -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    let path = directory.join("signing.key");
    fs::write(&path, format!("{KEY_ID} {}\n", HEXLOWER.encode(&[SEED_BYTE; SECRET_KEY_LENGTH])))?;
    fs::set_permissions(&path, Permissions::from_mode(mode))?;
    Ok(path)
}


fn signature_over(document: &str, key_id: &str) -> String {
    format!(
        "key {key_id}\nsignature {}\n{document}",
        HEXLOWER.encode(&signing_key().sign(document.as_bytes()).to_bytes())
    )
}


#[test]
fn a_signed_package_verifies_and_lists_its_files() -> TestResult {
    let directory = signed_dir()?;
    let verified = verify_package(directory.path(), &trusted(NOT_AFTER)?, NOW)?;
    assert_eq!(verified.manifest.name, "example-sync");
    assert_eq!(verified.files, vec![MANIFEST_NAME.to_owned(), "main.py".to_owned()]);
    Ok(())
}


#[test]
fn a_changed_manifest_or_code_byte_is_refused_naming_the_file() -> TestResult {
    let manifest = signed_dir()?;
    put(manifest.path(), MANIFEST_NAME, manifest_with("1.2.3", "1.2.4").as_bytes())?;
    assert!(matches!(verdict(manifest.path())?, ConnectorError::FileChanged { path } if path == MANIFEST_NAME));
    let code = signed_dir()?;
    put(code.path(), "main.py", b"print(2)")?;
    assert!(matches!(verdict(code.path())?, ConnectorError::FileChanged { path } if path == "main.py"));
    Ok(())
}


#[test]
fn an_added_a_removed_and_a_renamed_file_are_refused_naming_the_file() -> TestResult {
    let added = signed_dir()?;
    put(added.path(), "extra.py", b"x")?;
    assert!(matches!(verdict(added.path())?, ConnectorError::FileAdded { path } if path == "extra.py"));
    let removed = signed_dir()?;
    fs::remove_file(removed.path().join("main.py"))?;
    assert!(matches!(verdict(removed.path())?, ConnectorError::FileRemoved { path } if path == "main.py"));
    let renamed = signed_dir()?;
    fs::rename(renamed.path().join("main.py"), renamed.path().join("other.py"))?;
    assert!(matches!(verdict(renamed.path())?, ConnectorError::FileAdded { path } if path == "other.py"));
    Ok(())
}


#[test]
fn a_signature_over_the_manifest_alone_is_refused_when_other_code_is_present() -> TestResult {
    let directory = signed_dir()?;
    let manifest_only = read_package(directory.path())?;
    let mut files = manifest_only.files.clone();
    files.remove("main.py");
    put(
        directory.path(),
        SIGNATURE_NAME,
        signature_over(&signed_document(&files), KEY_ID).as_bytes(),
    )?;
    assert!(matches!(verdict(directory.path())?, ConnectorError::FileAdded { path } if path == "main.py"));
    Ok(())
}


#[test]
fn a_tampered_signature_or_document_does_not_verify() -> TestResult {
    let directory = signed_dir()?;
    let text = fs::read_to_string(directory.path().join(SIGNATURE_NAME))?;
    let flipped = text.replacen("signature ", &format!("signature {FLIPPED_DIGIT}"), 1);
    put(directory.path(), SIGNATURE_NAME, flipped.as_bytes())?;
    assert!(matches!(verdict(directory.path())?, ConnectorError::MalformedSignature));
    let mut bytes = HEXLOWER.decode(
        text.lines()
            .nth(1)
            .and_then(|line| line.strip_prefix("signature "))
            .ok_or("no signature")?
            .as_bytes(),
    )?;
    bytes.rotate_left(1);
    let rotated = text.replacen(
        text.lines().nth(1).ok_or("no line")?,
        &format!("signature {}", HEXLOWER.encode(&bytes)),
        1,
    );
    put(directory.path(), SIGNATURE_NAME, rotated.as_bytes())?;
    assert!(matches!(verdict(directory.path())?, ConnectorError::BadSignature));
    let edited = text.replacen("main.py", "main.pz", 1);
    put(directory.path(), SIGNATURE_NAME, edited.as_bytes())?;
    assert!(matches!(verdict(directory.path())?, ConnectorError::BadSignature));
    Ok(())
}


#[test]
fn an_unknown_key_an_expired_key_and_a_wrong_publisher_are_refused() -> TestResult {
    let directory = signed_dir()?;
    let package = read_package(directory.path())?;
    let other = key_file_text("other-key", PUBLISHER, &public_hex(), NOT_AFTER);
    let unknown = parse_trusted_keys(&other, "keys.yaml")?;
    assert!(matches!(check_package(&package, &unknown, NOW), Err(ConnectorError::UnknownKey { key_id }) if key_id == KEY_ID));
    assert!(check_package(&package, &trusted(NOT_AFTER)?, NOT_AFTER).is_ok());
    assert!(matches!(check_package(&package, &trusted(NOT_AFTER)?, NOT_AFTER + 1), Err(ConnectorError::KeyExpired { key_id }) if key_id == KEY_ID));
    assert!(matches!(
        check_package(&package, &trusted(NOW - 1)?, NOW),
        Err(ConnectorError::KeyExpired { .. })
    ));
    let other_publisher = parse_trusted_keys(&key_file_text(KEY_ID, "other", &public_hex(), NOT_AFTER), "keys.yaml")?;
    assert!(matches!(
        check_package(&package, &other_publisher, NOW),
        Err(ConnectorError::WrongPublisher)
    ));
    Ok(())
}


#[test]
fn a_package_without_a_signature_file_is_refused() -> TestResult {
    let directory = signed_dir()?;
    fs::remove_file(directory.path().join(SIGNATURE_NAME))?;
    assert!(matches!(verdict(directory.path())?, ConnectorError::MissingSignature));
    Ok(())
}


#[test]
fn a_signed_but_invalid_manifest_is_refused_at_verification_and_at_signing() -> TestResult {
    let directory = signed_dir()?;
    put(directory.path(), MANIFEST_NAME, format!("{VALID_MANIFEST}extra: 1\n").as_bytes())?;
    let package = read_package(directory.path())?;
    assert!(matches!(
        sign_package(&package, KEY_ID, &signing_key()),
        Err(ConnectorError::Document { .. })
    ));
    write_signature(directory.path(), &signature_over(&signed_document(&package.files), KEY_ID))?;
    assert!(matches!(verdict(directory.path())?, ConnectorError::Document { .. }));
    Ok(())
}


#[test]
fn every_malformed_signature_file_is_refused() -> TestResult {
    let good = signed_dir()?;
    let text = fs::read_to_string(good.path().join(SIGNATURE_NAME))?;
    let cases: Vec<Vec<u8>> = vec![
        vec![NOT_UTF8],
        b"key a\n".to_vec(),
        text.replacen("key ", "kex ", 1).into_bytes(),
        text.replacen("signature ", "sig ", 1).into_bytes(),
        text.replacen(KEY_ID, "-bad", 1).into_bytes(),
        format!("key {KEY_ID}\nsignature zz\n{MAGIC_LINE}").into_bytes(),
        format!("key {KEY_ID}\nsignature 00\n{MAGIC_LINE}").into_bytes(),
    ];
    cases.iter().try_for_each(|bytes| {
        assert!(matches!(parse_signature_file(bytes), Err(ConnectorError::MalformedSignature)));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    let bad_documents = [
        format!("{MAGIC_LINE}main.py abc\n"),
        format!("{MAGIC_LINE}main.py abc x\n"),
        format!("{MAGIC_LINE}main.py abc 1\nmain.py abc 1\n"),
        "no magic\n".to_owned(),
    ];
    bad_documents.iter().try_for_each(|document| {
        assert!(matches!(read_document(document), Err(ConnectorError::MalformedSignature)));
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    assert!(read_document(MAGIC_LINE)?.is_empty());
    Ok(())
}


#[test]
fn a_package_that_cannot_be_read_is_refused() -> TestResult {
    let directory = signed_dir()?;
    symlink("main.py", directory.path().join("link"))?;
    assert!(matches!(verdict(directory.path())?, ConnectorError::Symlink { .. }));
    Ok(())
}


#[test]
fn sign_directory_signs_with_a_private_key_file_and_replaces_a_previous_signature() -> TestResult {
    let directory = signed_dir()?;
    let keys = tempfile::tempdir()?;
    let path = key_file(keys.path(), OWNER_ONLY)?;
    put(directory.path(), "main.py", b"print(3)")?;
    assert_eq!(sign_directory(directory.path(), &path)?, TWO_FILES);
    assert!(verify_package(directory.path(), &trusted(NOT_AFTER)?, NOW).is_ok());
    Ok(())
}


#[test]
fn a_group_readable_or_symlinked_key_file_is_refused() -> TestResult {
    let directory = signed_dir()?;
    let keys = tempfile::tempdir()?;
    let readable = key_file(keys.path(), GROUP_READABLE)?;
    assert!(matches!(sign_directory(directory.path(), &readable), Err(ConnectorError::SecretFile(_))));
    let private = key_file(keys.path(), OWNER_ONLY)?;
    let link = keys.path().join("link.key");
    symlink(&private, &link)?;
    assert!(matches!(sign_directory(directory.path(), &link), Err(ConnectorError::SecretFile(_))));
    Ok(())
}


#[test]
fn sign_directory_refuses_an_invalid_manifest_and_writes_nothing() -> TestResult {
    let directory = tempfile::tempdir()?;
    put(directory.path(), MANIFEST_NAME, b"name: -x\n")?;
    let keys = tempfile::tempdir()?;
    assert!(sign_directory(directory.path(), &key_file(keys.path(), OWNER_ONLY)?).is_err());
    assert!(!directory.path().join(SIGNATURE_NAME).exists());
    Ok(())
}


#[test]
fn writing_a_signature_fails_cleanly_when_the_directory_or_target_is_unusable() -> TestResult {
    let directory = tempfile::tempdir()?;
    assert!(matches!(
        write_signature(&directory.path().join("absent"), "x"),
        Err(ConnectorError::Io { .. })
    ));
    fs::create_dir(directory.path().join(SIGNATURE_NAME))?;
    assert!(matches!(write_signature(directory.path(), "x"), Err(ConnectorError::Io { .. })));
    Ok(())
}


#[test]
fn the_command_line_verifies_signs_and_reports_usage() -> TestResult {
    let directory = signed_dir()?;
    let keys = tempfile::tempdir()?;
    let keys_file = keys.path().join("trusted.yaml");
    fs::write(&keys_file, key_file_text(KEY_ID, PUBLISHER, &public_hex(), NOT_AFTER))?;
    let package = directory.path().display().to_string();
    let trusted_path = keys_file.display().to_string();
    let mut out = Vec::new();
    run(&["verify", &package, &trusted_path], NOW, &mut out)?;
    assert_eq!(String::from_utf8(out)?, "verified example-sync 1.2.3 publisher=acme files=2\n");
    let key = key_file(keys.path(), OWNER_ONLY)?.display().to_string();
    let mut signed = Vec::new();
    run(&["sign", &package, &key], NOW, &mut signed)?;
    assert_eq!(String::from_utf8(signed)?, format!("signed {package} files=2\n"));
    let mut expired = Vec::new();
    assert!(matches!(
        run(&["verify", &package, &trusted_path], NOT_AFTER + 1, &mut expired),
        Err(ConnectorError::KeyExpired { .. })
    ));
    assert!(matches!(run(&["nope"], NOW, &mut expired), Err(ConnectorError::Usage(text)) if text == USAGE));
    assert!(expired.is_empty());
    Ok(())
}


#[test]
fn the_clock_before_the_epoch_is_refused() -> TestResult {
    assert_eq!(epoch_seconds(Ok(Duration::from_secs(NOW)))?, NOW);
    let before = UNIX_EPOCH.duration_since(SystemTime::now());
    assert!(matches!(epoch_seconds(before), Err(ConnectorError::Clock)));
    Ok(())
}


struct Closed;


impl Write for Closed {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("closed"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


#[test]
fn an_empty_output_writer_failure_is_reported() -> TestResult {
    let directory = signed_dir()?;
    let keys = tempfile::tempdir()?;
    let keys_file = keys.path().join("trusted.yaml");
    fs::write(&keys_file, key_file_text(KEY_ID, PUBLISHER, &public_hex(), NOT_AFTER))?;
    let package = directory.path().display().to_string();
    let trusted_path = keys_file.display().to_string();
    assert!(matches!(
        run(&["verify", &package, &trusted_path], NOW, &mut Closed),
        Err(ConnectorError::Output(_))
    ));
    let key = key_file(keys.path(), OWNER_ONLY)?.display().to_string();
    assert!(matches!(run(&["sign", &package, &key], NOW, &mut Closed), Err(ConnectorError::Output(_))));
    Ok(())
}


#[test]
fn the_command_line_reports_an_unreadable_keys_file_or_signing_failure() -> TestResult {
    let directory = signed_dir()?;
    let keys = tempfile::tempdir()?;
    let package = directory.path().display().to_string();
    let absent = keys.path().join("absent.yaml").display().to_string();
    let mut out = Vec::new();
    assert!(matches!(
        run(&["verify", &package, &absent], NOW, &mut out),
        Err(ConnectorError::Io { .. })
    ));
    assert!(matches!(
        run(&["sign", &package, &absent], NOW, &mut out),
        Err(ConnectorError::SecretFile(_))
    ));
    assert!(out.is_empty());
    Ok(())
}


#[test]
fn a_signing_key_file_over_the_cap_or_a_missing_package_is_refused() -> TestResult {
    let directory = signed_dir()?;
    let keys = tempfile::tempdir()?;
    let big = keys.path().join("big.key");
    fs::write(&big, vec![b' '; MAX_KEY_FILE_BYTES as usize + 1])?;
    fs::set_permissions(&big, Permissions::from_mode(OWNER_ONLY))?;
    assert!(matches!(sign_directory(directory.path(), &big), Err(ConnectorError::FileTooLarge { .. })));
    let key = key_file(keys.path(), OWNER_ONLY)?;
    assert!(matches!(
        sign_directory(&directory.path().join("absent"), &key),
        Err(ConnectorError::Io { .. })
    ));
    Ok(())
}


#[test]
fn a_valid_signature_over_an_unreadable_document_is_refused() -> TestResult {
    let directory = signed_dir()?;
    put(directory.path(), SIGNATURE_NAME, signature_over("not a document\n", KEY_ID).as_bytes())?;
    assert!(matches!(verdict(directory.path())?, ConnectorError::MalformedSignature));
    Ok(())
}
