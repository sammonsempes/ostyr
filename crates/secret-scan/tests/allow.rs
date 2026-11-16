#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use secret_scan::allow::{checked_rules, key_path_text, read_rules, CUT_MARK, MAX_KEY_PATH, MAX_RULES_BYTES};
use secret_scan::scan::ScanError;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use tempfile::TempDir;
use types::TestResult;


const GROUP_WRITABLE_MODE: u32 = 0o664;


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
    assert!(checked_rules(&fs::read_to_string(committed_rules())?)?.contains_key("rules"));
    Ok(())
}


fn caller() -> u32 {
    rustix::process::geteuid().as_raw()
}


#[test]
fn the_rules_file_is_read_bounded_checked_and_without_following_a_link() -> TestResult {
    let (dir, rules) = rules_file("title = \"x\"\n")?;
    assert_eq!(read_rules(&rules, caller())?, "title = \"x\"\n");
    let big = dir.path().join("big.toml");
    fs::write(&big, vec![b'#'; MAX_RULES_BYTES as usize + 1])?;
    assert!(matches!(read_rules(&big, caller()), Err(ScanError::BadRules("too large"))));
    let link = dir.path().join("link.toml");
    symlink(&rules, &link)?;
    assert!(matches!(read_rules(&link, caller()), Err(ScanError::Io(_))));
    assert!(matches!(read_rules(&dir.path().join("missing.toml"), caller()), Err(ScanError::Io(_))));
    Ok(())
}


#[test]
fn the_opened_handle_is_checked_for_kind_owner_and_mode() -> TestResult {
    let (dir, rules) = rules_file("title = \"x\"\n")?;
    assert!(matches!(
        read_rules(Path::new("rules.toml"), caller()),
        Err(ScanError::BadRules("not absolute"))
    ));
    assert!(matches!(read_rules(dir.path(), caller()), Err(ScanError::BadRules("not a regular file"))));
    assert!(matches!(
        read_rules(&rules, caller().wrapping_add(1)),
        Err(ScanError::BadRules("not owned by the caller"))
    ));
    fs::set_permissions(&rules, fs::Permissions::from_mode(GROUP_WRITABLE_MODE))?;
    assert!(matches!(
        read_rules(&rules, caller()),
        Err(ScanError::BadRules("writable by group or others"))
    ));
    let fifo = dir.path().join("rules.fifo");
    assert!(Command::new("mkfifo").arg(&fifo).status()?.success());
    assert!(matches!(read_rules(&fifo, caller()), Err(ScanError::BadRules("not a regular file"))));
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
