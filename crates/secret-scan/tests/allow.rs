#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use secret_scan::allow::{allowlist_patterns, check_work_dir_rules, read_rules, MAX_RULES_BYTES};
use secret_scan::scan::ScanError;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use types::TestResult;


const NON_UTF8_BYTE: u8 = 0xff;


const SAMPLE: &str = "
[allowlist]
paths = ['''global-one''', '''global-two''']
[[allowlists]]
paths = ['''many-one''']
[[allowlists]]
description = \"no paths\"
[[rules]]
id = \"a\"
[[rules.allowlists]]
paths = ['''rule-one''']
[rules.allowlist]
paths = ['''rule-single''', 7]
[[rules]]
id = \"b\"
";


const EXPECTED: [&str; 5] = ["global-one", "global-two", "many-one", "rule-single", "rule-one"];


fn committed_rules() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/gitleaks-8.26.0.toml")
}


fn rules_file(text: &str) -> Result<(TempDir, PathBuf), Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let path = dir.path().join("rules.toml");
    fs::write(&path, text)?;
    Ok((dir, path))
}


#[test]
fn every_allowlist_paths_table_is_read() -> TestResult {
    let mut found = allowlist_patterns(SAMPLE)?;
    found.sort();
    let mut expected: Vec<String> = EXPECTED.iter().map(|text| text.to_string()).collect();
    expected.sort();
    assert_eq!(found, expected);
    assert!(allowlist_patterns("title = \"none\"")?.is_empty());
    assert!(matches!(allowlist_patterns("= not toml ["), Err(ScanError::BadRules("not valid TOML"))));
    Ok(())
}


#[test]
fn the_committed_rules_refuse_every_work_directory_their_allowlist_matches() -> TestResult {
    let rules = committed_rules();
    assert!(allowlist_patterns(&read_rules(&rules)?)?.len() > EXPECTED.len());
    [
        "/var/lib/env/lib/ss",
        "/var/lib/venv/lib64/ss",
        "/srv/lib/python3.11/ss",
        "/srv/app-1.2.dist-info/ss",
        "/srv/verification-metadata.xml/ss",
        "/srv/Database.refactorlog/ss",
        "/a/node_modules/work",
        "/a/vendor/github.com/work",
        "/a/bower_components/x/y",
        "/a/gitleaks.toml/w",
        "/a/vendor/bundle/w",
    ]
    .iter()
    .try_for_each(|path| match check_work_dir_rules(&rules, Path::new(path)) {
        Err(ScanError::BadSettings("work directory matches an allowlist path of the rules")) => Ok(()),
        other => Err(format!("not refused: {path}: {other:?}")),
    })?;
    ["/var/lib/secret-scan/work", "/root/work", "/var/lib/ostyr/secret-scan"]
        .iter()
        .try_for_each(|path| check_work_dir_rules(&rules, Path::new(path)))?;
    Ok(())
}


#[test]
fn a_pattern_that_does_not_compile_is_a_refusal_not_a_skip() -> TestResult {
    let (_dir, rules) = rules_file("[allowlist]\npaths = ['''(?!lookahead)''']\n")?;
    assert!(matches!(
        check_work_dir_rules(&rules, Path::new("/var/lib/work")),
        Err(ScanError::BadRules("allowlist pattern does not compile"))
    ));
    Ok(())
}


#[test]
fn the_rules_file_is_read_bounded_and_without_following_a_link() -> TestResult {
    let (dir, rules) = rules_file("title = \"x\"\n")?;
    assert_eq!(read_rules(&rules)?, "title = \"x\"\n");
    let big = dir.path().join("big.toml");
    fs::write(&big, vec![b'#'; MAX_RULES_BYTES as usize + 1])?;
    assert!(matches!(read_rules(&big), Err(ScanError::BadRules("too large"))));
    let link = dir.path().join("link.toml");
    symlink(&rules, &link)?;
    assert!(matches!(read_rules(&link), Err(ScanError::Io(_))));
    assert!(matches!(check_work_dir_rules(&link, Path::new("/var/lib/work")), Err(ScanError::Io(_))));
    assert!(matches!(
        check_work_dir_rules(&big, Path::new("/var/lib/work")),
        Err(ScanError::BadRules("too large"))
    ));
    Ok(())
}


#[test]
fn a_work_directory_that_is_not_utf8_is_refused() -> TestResult {
    let (_dir, rules) = rules_file("title = \"x\"\n")?;
    let odd = PathBuf::from(OsString::from_vec(vec![b'/', b'w', NON_UTF8_BYTE]));
    assert!(matches!(
        check_work_dir_rules(&rules, &odd),
        Err(ScanError::BadSettings("work directory is not UTF-8"))
    ));
    Ok(())
}


#[test]
fn a_work_directory_that_is_not_normalised_is_refused_before_any_probe() -> TestResult {
    let (_dir, rules) = rules_file("title = \"x\"\n")?;
    [
        "/var/lib/env//lib/ss",
        "/var/lib/env/./lib/ss",
        "/var/lib/env/../env/lib/ss",
        "/var/lib/ok/",
        "/",
        "var/lib/ok",
        "",
    ]
    .iter()
    .try_for_each(|path| match check_work_dir_rules(&rules, Path::new(path)) {
        Err(ScanError::BadSettings("work directory is not a normalised absolute path")) => Ok(()),
        other => Err(format!("not refused: {path:?}: {other:?}")),
    })?;
    check_work_dir_rules(&rules, Path::new("/var/lib/ok"))?;
    Ok(())
}
