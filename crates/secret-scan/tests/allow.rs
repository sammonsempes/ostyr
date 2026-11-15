#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use secret_scan::allow::{check_normalised, checked_rules, key_path_text, read_rules, CUT_MARK, MAX_KEY_PATH, MAX_RULES_BYTES};
use secret_scan::scan::ScanError;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use types::TestResult;


const NON_UTF8_BYTE: u8 = 0xff;


const EXTRA_KEY_CHARS: usize = 40;


const KEY_FACTOR: usize = 3;


const SAMPLE: &str = "
[allowlist]
paths = ['''global-one''']
[[allowlists]]
paths = ['''many-one''']
[[rules]]
id = \"a\"
[[rules.allowlists]]
paths = ['''rule-one''']
[rules.allowlist]
paths = ['''rule-single''']
";


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
fn the_documented_keys_are_accepted_and_kept() -> TestResult {
    let table = checked_rules(SAMPLE)?;
    assert!(table.contains_key("allowlist") && table.contains_key("allowlists") && table.contains_key("rules"));
    assert!(checked_rules("title = \"none\"")?.contains_key("title"));
    assert!(matches!(checked_rules("= not toml ["), Err(ScanError::BadRules("not valid TOML"))));
    assert!(checked_rules(&read_rules(&committed_rules())?)?.contains_key("rules"));
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
    Ok(())
}


#[test]
fn a_work_directory_that_is_not_utf8_is_refused() -> TestResult {
    let odd = PathBuf::from(OsString::from_vec(vec![b'/', b'w', NON_UTF8_BYTE]));
    assert!(matches!(
        check_normalised(&odd),
        Err(ScanError::BadSettings("work directory is not UTF-8"))
    ));
    Ok(())
}


#[test]
fn a_work_directory_that_is_not_normalised_is_refused() -> TestResult {
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
    .try_for_each(|path| match check_normalised(Path::new(path)) {
        Err(ScanError::BadSettings("work directory is not a normalised absolute path")) => Ok(()),
        other => Err(format!("not refused: {path:?}: {other:?}")),
    })?;
    assert_eq!(check_normalised(Path::new("/var/lib/ok"))?, "/var/lib/ok");
    Ok(())
}


#[test]
fn a_work_directory_with_a_control_byte_is_refused_and_a_non_ascii_one_is_accepted() -> TestResult {
    ["/var/lib/a\x0bb", "/var/lib/a\nb", "/var/lib/a\x7fb", "/var/lib/a\x1fb"]
        .iter()
        .try_for_each(|path| match check_normalised(Path::new(path)) {
            Err(ScanError::BadSettings("work directory holds a control character")) => Ok(()),
            other => Err(format!("not refused: {path:?}: {other:?}")),
        })?;
    assert_eq!(check_normalised(Path::new("/var/lib/ \u{e9}work"))?, "/var/lib/ \u{e9}work");
    Ok(())
}


#[test]
fn every_lenient_form_is_refused_with_its_key_path() -> TestResult {
    let rule = "[[rules]]\nid = \"a\"\n";
    let cases = [
        ("[extend]\nuseDefault = true\n".to_string(), "extend"),
        ("[Extend]\nuseDefault = true\n".to_string(), "Extend"),
        ("\"extend.useDefault\" = true\n".to_string(), "extend.useDefault"),
        ("EXTEND = { useDefault = true }\n".to_string(), "EXTEND"),
        ("[extend]\n".to_string(), "extend"),
        ("extend = 1\n".to_string(), "extend"),
        ("[Allowlist]\npaths = ['''x''']\n".to_string(), "Allowlist"),
        ("[allowlist]\nPaths = ['''x''']\n".to_string(), "allowlist.Paths"),
        ("[allowlist]\npaths = '''x'''\n".to_string(), "allowlist.paths"),
        ("[allowlist]\npaths = ['''x''', 7]\n".to_string(), "allowlist.paths"),
        ("\"allowlist.paths\" = ['''x''']\n".to_string(), "allowlist.paths"),
        ("[allowlist]\nstopWords = ['''x''']\n".to_string(), "allowlist.stopWords"),
        ("allowlist = 1\n".to_string(), "allowlist"),
        ("allowlists = 1\n".to_string(), "allowlists"),
        ("allowlists = [1]\n".to_string(), "allowlists[0]"),
        ("rules = 1\n".to_string(), "rules"),
        ("rules = [1]\n".to_string(), "rules[0]"),
        ("minVersion = \"v8.0.0\"\n".to_string(), "minVersion"),
        ("[[rules]]\nbogus = 1\n".to_string(), "rules[0].bogus"),
        ("[[rules]]\nkeywords = '''x'''\n".to_string(), "rules[0].keywords"),
        (format!("{rule}[[rules.Allowlists]]\npaths = ['''x''']\n"), "rules[0].Allowlists"),
        (format!("{rule}[[rules.allowlists]]\npaths = '''x'''\n"), "rules[0].allowlists[0].paths"),
        (format!("{rule}[rules.allowlist]\nbogus = 1\n"), "rules[0].allowlist.bogus"),
        (
            format!("{rule}[rules.allowlist]\ntargetRules = ['''a''']\n"),
            "rules[0].allowlist.targetRules",
        ),
        (format!("{rule}allowlist = 1\n"), "rules[0].allowlist"),
    ];
    cases.iter().try_for_each(|(text, key)| match checked_rules(text) {
        Err(ScanError::BadRulesKey(found)) if found == *key => Ok(()),
        other => Err(format!("not refused as {key}: {text:?}: {other:?}")),
    })?;
    assert!(checked_rules("[allowlist]\ntargetRules = ['''a''']\npaths = ['''p''']\n").is_ok());
    Ok(())
}


#[test]
fn a_key_path_is_printable_ascii_and_cut_with_a_visible_mark() -> TestResult {
    assert_eq!(key_path_text("a.b[0]"), "a.b[0]");
    assert_eq!(key_path_text("caf\u{e9}\n"), "caf??");
    let long = key_path_text(&"k".repeat(MAX_KEY_PATH + EXTRA_KEY_CHARS));
    assert_eq!(long.len(), MAX_KEY_PATH + CUT_MARK.len());
    assert!(long.ends_with(CUT_MARK));
    assert_eq!(key_path_text(&"k".repeat(MAX_KEY_PATH)).len(), MAX_KEY_PATH);
    let refused = checked_rules(&format!("\"{}\" = 1\n", "z".repeat(MAX_KEY_PATH * KEY_FACTOR)));
    assert!(matches!(refused, Err(ScanError::BadRulesKey(found)) if found.len() == MAX_KEY_PATH + CUT_MARK.len()));
    Ok(())
}
