use crate::types::TestResult;
use std::fs::OpenOptions;
use std::io::Write;
use std::time::Duration;
use sys_windows::signature::{open_for_verification, verify_signed_file};
use sys_windows::types::{SignatureError, SignatureOutcome};


const DEADLINE: Duration = Duration::from_secs(120);


const MICROSOFT_SIGNED_CANDIDATES: [&str; 2] = ["C:\\Program Files\\Windows Defender\\MpCmdRun.exe", "C:\\Windows\\Sysmon64.exe"];


const ROOT_2010: &str = "df545bf919a2439c36983b54cdfc903dfa4f37d3996d8d84b4c31eec6f3c163e";


const ROOT_2011: &str = "847df6a78497943f27fc72eb93f9a637320a02b561d0a91b09e87a7807ed7c61";


#[test]
fn a_microsoft_file_is_judged_on_its_primary_signer_and_a_pinned_root() -> TestResult {
    let path = MICROSOFT_SIGNED_CANDIDATES
        .iter()
        .find(|candidate| std::path::Path::new(candidate).exists())
        .ok_or("no Microsoft-signed file with an embedded signature on this machine")?;
    let file = open_for_verification(std::path::Path::new(path))?;
    let signed = match verify_signed_file(&file, DEADLINE)? {
        SignatureOutcome::Trusted(signed) | SignatureOutcome::RevocationUnknown(signed) => signed,
    };
    assert!(signed.leaf_subject.contains("O=Microsoft Corporation"), "{}", signed.leaf_subject);
    assert!(
        signed.root_sha256 == ROOT_2010 || signed.root_sha256 == ROOT_2011,
        "{}",
        signed.root_sha256
    );
    assert!(signed.version.product_name.is_some());
    Ok(())
}


#[test]
fn a_missing_file_is_a_read_error_with_its_kind() -> TestResult {
    let directory = tempfile::tempdir()?;
    let result = open_for_verification(&directory.path().join("absent.exe"));
    assert!(matches!(
        result,
        Err(SignatureError::Read {
            kind: std::io::ErrorKind::NotFound
        })
    ));
    Ok(())
}


#[test]
fn an_unsigned_executable_is_refused_by_name() -> TestResult {
    let file = open_for_verification(&std::env::current_exe()?)?;
    let result = verify_signed_file(&file, DEADLINE);
    assert!(matches!(result, Err(SignatureError::Unsigned)), "{result:?}");
    Ok(())
}


#[test]
fn a_held_file_cannot_be_written_or_deleted_by_another_open() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("held.exe");
    std::fs::write(&path, b"MZ")?;
    let held = open_for_verification(&path)?;
    assert!(OpenOptions::new().write(true).open(&path).is_err());
    assert!(OpenOptions::new()
        .append(true)
        .open(&path)
        .and_then(|mut file| file.write_all(b"x"))
        .is_err());
    assert!(std::fs::remove_file(&path).is_err());
    assert!(std::fs::rename(&path, directory.path().join("moved.exe")).is_err());
    drop(held);
    Ok(())
}
