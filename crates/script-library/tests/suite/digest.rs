use crate::common::{manifest_with, refusal, EMPTY_SHA256};
use crate::types::TestResult;
use script_library::digest::check_digest;
use script_library::error::ScriptError;
use script_library::model::Interpreter;


#[test]
fn matching_bytes_are_returned_unchanged() -> TestResult {
    let manifest = manifest_with(Interpreter::Bash, vec![]);
    assert_eq!(manifest.sha256, EMPTY_SHA256);
    assert_eq!(check_digest(&manifest, Vec::new())?, Vec::<u8>::new());
    let abc = script_library::model::Manifest {
        sha256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad".to_string(),
        ..manifest
    };
    assert_eq!(check_digest(&abc, b"abc".to_vec())?, b"abc".to_vec());
    Ok(())
}


#[test]
fn mismatch_is_refused() -> TestResult {
    let manifest = manifest_with(Interpreter::Bash, vec![]);
    let error = refusal(check_digest(&manifest, b"echo changed".to_vec()))?;
    assert!(matches!(error, ScriptError::DigestMismatch));
    Ok(())
}
