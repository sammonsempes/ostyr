#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use secret_scan::allow::{
    allowlist_patterns, check_normalised, check_probes, compile_pattern, is_wide_pattern, key_path_text, load_allowlist, read_rules, CUT_MARK,
    MAX_KEY_PATH, MAX_RULES_BYTES,
};
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
paths = ['''rule-single''']
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


fn check_work_dir_rules(rules: &Path, work_dir: &Path) -> Result<(), ScanError> {
    load_allowlist(rules, work_dir).map(drop)
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
    cases.iter().try_for_each(|(text, key)| match allowlist_patterns(text) {
        Err(ScanError::BadRulesKey(found)) if found == *key => Ok(()),
        other => Err(format!("not refused as {key}: {text:?}: {other:?}")),
    })?;
    assert_eq!(
        allowlist_patterns("[allowlist]\ntargetRules = ['''a''']\npaths = ['''p''']\n")?,
        vec!["p".to_string()]
    );
    let (_dir, rules) = rules_file("[extend]\nuseDefault = true\n")?;
    assert!(matches!(
        check_work_dir_rules(&rules, Path::new("/var/lib/ok")),
        Err(ScanError::BadRulesKey(found)) if found == "extend"
    ));
    assert!(allowlist_patterns(&read_rules(&committed_rules())?).is_ok());
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
    let refused = allowlist_patterns(&format!("\"{}\" = 1\n", "z".repeat(MAX_KEY_PATH * KEY_FACTOR)));
    assert!(matches!(refused, Err(ScanError::BadRulesKey(found)) if found.len() == MAX_KEY_PATH + CUT_MARK.len()));
    Ok(())
}


#[test]
fn the_probe_covers_the_scan_root_the_tree_and_a_leaf() -> TestResult {
    let private = Path::new("/var/lib/ok/secret-scan-Ab3xYz");
    [
        "(?:^|/)data$",
        "(?:^|/)tree$",
        "(?:^|/)x$",
        "secret-scan-[a-zA-Z0-9]{6}/",
        "Ab3xYz",
        "secret-scan-",
    ]
    .iter()
    .try_for_each(|pattern| match check_probes(&[compile_pattern(pattern)?], private) {
        Err(ScanError::BadSettings("work directory matches an allowlist path of the rules")) => Ok::<(), Box<dyn std::error::Error>>(()),
        other => Err(format!("not refused: {pattern}: {other:?}").into()),
    })?;
    check_probes(&[compile_pattern("elsewhere")?], private)?;
    check_probes(&[], private)?;
    Ok(())
}


#[test]
fn a_pattern_on_the_data_or_tree_directory_is_refused_at_load() -> TestResult {
    ["(?:^|/)data$", "(?:^|/)tree$", "secret-scan-[a-zA-Z0-9]{6}/"]
        .iter()
        .try_for_each(|pattern| {
            let (_dir, rules) = rules_file(&format!("[allowlist]\npaths = ['''{pattern}''']\n"))?;
            match check_work_dir_rules(&rules, Path::new("/var/lib/ok")) {
                Err(ScanError::BadSettings("work directory matches an allowlist path of the rules")) => Ok(()),
                other => Err(format!("not refused: {pattern}: {other:?}").into()),
            }
        })
}


#[test]
fn classes_are_ascii_like_go() -> TestResult {
    let word = compile_pattern("^\\w+$")?;
    assert!(!word.is_match("\u{e9}".as_bytes()));
    assert!(word.is_match(b"abc"));
    Ok(())
}


#[test]
fn a_non_ascii_work_directory_is_refused() -> TestResult {
    let (_dir, rules) = rules_file("[allowlist]\npaths = ['''\\bwork\\b''']\n")?;
    assert!(matches!(
        check_work_dir_rules(&rules, Path::new("/var/lib/\u{e9}work")),
        Err(ScanError::BadSettings("work directory is not ASCII"))
    ));
    assert!(matches!(
        check_work_dir_rules(&rules, Path::new("/var/lib/work")),
        Err(ScanError::BadSettings("work directory matches an allowlist path of the rules"))
    ));
    Ok(())
}


#[test]
fn a_pattern_with_non_ascii_text_or_a_wide_escape_is_refused() -> TestResult {
    [
        "(?i)wor\\x{212a}/",
        "(?i)wor\u{212a}",
        "lib/\\xe9work",
        "(?i)lib/\u{c9}WORK",
        "[\u{e9}]",
        "\\u00e9",
        "\\U000000e9",
        "\\pL",
        "\\PL",
        "\\N{LATIN SMALL LETTER E WITH ACUTE}",
    ]
    .iter()
    .try_for_each(|pattern| {
        let (_dir, rules) = rules_file(&format!("[allowlist]\npaths = ['''{pattern}''']\n"))?;
        match check_work_dir_rules(&rules, Path::new("/var/lib/work")) {
            Err(ScanError::BadRules("allowlist pattern is not ASCII or holds a Unicode escape")) => Ok::<(), Box<dyn std::error::Error>>(()),
            other => Err(format!("not refused: {pattern}: {other:?}").into()),
        }
    })?;
    assert!(is_wide_pattern("\\\\\\x"));
    assert!(!is_wide_pattern("\\\\x"));
    assert!(!is_wide_pattern("a\\.b\\d"));
    Ok(())
}


#[test]
fn a_pattern_counting_characters_after_the_tree_is_seen_by_the_longer_leaves() -> TestResult {
    let private = Path::new("/var/lib/work/secret-scan-Ab3xYz");
    ["secret-scan-\\w{6}/data/tree/..", "tree/x{8}$", "tree/x{2}$"]
        .iter()
        .try_for_each(|pattern| match check_probes(&[compile_pattern(pattern)?], private) {
            Err(ScanError::BadSettings("work directory matches an allowlist path of the rules")) => Ok::<(), Box<dyn std::error::Error>>(()),
            other => Err(format!("not refused: {pattern}: {other:?}").into()),
        })
}


#[test]
fn check_normalised_returns_the_text_of_a_clean_path() -> TestResult {
    assert_eq!(check_normalised(Path::new("/var/lib/ok"))?, "/var/lib/ok");
    assert!(check_normalised(Path::new("/a/./b")).is_err());
    Ok(())
}
