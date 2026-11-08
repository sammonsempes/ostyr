use crate::common::{manifest_with, single};
use crate::types::TestResult;
use script_library::check::{check_manifest, is_identifier, is_library_path, is_sha256_hex};
use script_library::model::{Interpreter, ParamKind, MAX_NAME_LENGTH, SHA256_HEX_LENGTH};


#[test]
fn well_formed_manifest_passes() -> TestResult {
    check_manifest(&manifest_with(Interpreter::Python, vec![]))?;
    check_manifest(&single("days", ParamKind::Integer { min: 0, max: 1 }))?;
    Ok(())
}


#[test]
fn identifiers() -> TestResult {
    assert!(is_identifier("a"));
    assert!(is_identifier("a-b_9"));
    assert!(is_identifier(&format!("a{}", "b".repeat(MAX_NAME_LENGTH - 1))));
    assert!(!is_identifier(""));
    assert!(!is_identifier("9a"));
    assert!(!is_identifier("A"));
    assert!(!is_identifier("a b"));
    assert!(!is_identifier(&format!("a{}", "b".repeat(MAX_NAME_LENGTH))));
    Ok(())
}


#[test]
fn library_paths() -> TestResult {
    assert!(is_library_path("linux/cleanup.sh"));
    assert!(is_library_path("a.ps1"));
    ["", "/a", "\\a", "-a", "a\\b", "a\u{1}b", "a//b", "a/", "a/./b", "a/../b", ".."]
        .iter()
        .for_each(|path| assert!(!is_library_path(path), "{path:?}"));
    Ok(())
}


#[test]
fn digests() -> TestResult {
    assert!(is_sha256_hex(&"a".repeat(SHA256_HEX_LENGTH)));
    assert!(!is_sha256_hex(&"a".repeat(SHA256_HEX_LENGTH - 1)));
    assert!(!is_sha256_hex(&"A".repeat(SHA256_HEX_LENGTH)));
    Ok(())
}
