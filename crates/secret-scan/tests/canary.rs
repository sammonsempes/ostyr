#![cfg(unix)]
#[path = "common/types.rs"]
mod types;


use secret_scan::allow::{checked_rules, read_rules};
use secret_scan::canary::{canary_from, check_canaries, config_text, new_canary, widened_limits, Canary, NAME_PREFIX, REPORT_BYTES_PER_CANARY};
use secret_scan::copy::CopySummary;
use secret_scan::model::Limits;
use secret_scan::scan::ScanError;
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use toml::{Table, Value};
use types::TestResult;


const NAME_LENGTH: usize = 29;


const VALUE_LENGTH: usize = 45;


const NAME_BYTES: usize = 8;


const SHORT_BYTES: usize = 4;


const THREE: usize = 3;


const TWO: usize = 2;


const ENTROPY: f64 = 3.5;


const RANDOM: [u8; 24] = [
    0, 1, 2, 3, 4, 5, 6, 7, 255, 254, 253, 252, 251, 250, 249, 248, 16, 17, 18, 19, 20, 21, 22, 23,
];


fn fixed() -> Canary {
    Canary {
        name: "ostyr-canary-aaaa".to_string(),
        value: "ostyr-canary-bbbb".to_string(),
    }
}


fn shown(root: &str, dir: &str) -> String {
    format!("{root}/{dir}ostyr-canary-aaaa")
}


#[test]
fn a_canary_is_built_from_random_bytes_and_both_reads_can_fail() -> TestResult {
    let canary = canary_from(RANDOM.as_slice())?;
    assert_eq!(canary.name, "ostyr-canary-0001020304050607");
    assert_eq!(canary.value, "ostyr-canary-fffefdfcfbfaf9f81011121314151617");
    let short = RANDOM.get(..SHORT_BYTES).ok_or("short")?;
    let named_only = RANDOM.get(..NAME_BYTES).ok_or("short")?;
    assert!(matches!(canary_from(short), Err(ScanError::Io(_))));
    assert!(matches!(canary_from(named_only), Err(ScanError::Io(_))));
    Ok(())
}


#[test]
fn the_kernel_source_gives_a_fresh_canary_each_time() -> TestResult {
    let first = new_canary()?;
    let second = new_canary()?;
    assert_eq!((first.name.len(), first.value.len()), (NAME_LENGTH, VALUE_LENGTH));
    assert!(first.name.starts_with(NAME_PREFIX) && first.value.starts_with(NAME_PREFIX));
    assert!(first
        .value
        .bytes()
        .skip(NAME_PREFIX.len())
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
    assert_ne!(first, second);
    Ok(())
}


#[test]
fn the_config_keeps_the_operator_rules_and_adds_the_canary_rule() -> TestResult {
    let plain = config_text(&checked_rules("title = \"t\"\n")?)?.parse::<Table>()?;
    assert_eq!(plain.get("title").and_then(Value::as_str), Some("t"));
    let only = plain.get("rules").and_then(Value::as_array).ok_or("no rules")?;
    assert_eq!(only.len(), 1);
    let rules = "[allowlist]\npaths = ['''vendor/''']\n[[rules]]\nid = \"op\"\nregex = '''x+'''\nentropy = 3.5\nkeywords = [\"x\"]\n";
    let config = config_text(&checked_rules(rules)?)?.parse::<Table>()?;
    let list = config.get("rules").and_then(Value::as_array).ok_or("no rules")?;
    let ids: Vec<&str> = list.iter().filter_map(|rule| rule.get("id").and_then(Value::as_str)).collect();
    assert_eq!(ids, vec!["op", "ostyr-canary"]);
    let canary = list.last().and_then(|rule| rule.get("regex")).and_then(Value::as_str);
    assert_eq!(canary, Some("ostyr-canary-[0-9a-f]{32}"));
    assert_eq!(list.first().and_then(|rule| rule.get("entropy")).and_then(Value::as_float), Some(ENTROPY));
    let paths = config.get("allowlist").and_then(|table| table.get("paths")).and_then(Value::as_array);
    assert_eq!(paths.map(Vec::len), Some(1));
    Ok(())
}


#[test]
fn the_committed_rules_round_trip_with_one_more_rule() -> TestResult {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("rules/gitleaks-8.26.0.toml");
    let original = checked_rules(&read_rules(&path)?)?;
    let config = config_text(&original)?.parse::<Table>()?;
    let before = original.get("rules").and_then(Value::as_array).map(Vec::len).ok_or("no rules")?;
    let after = config.get("rules").and_then(Value::as_array).map(Vec::len).ok_or("no rules")?;
    assert_eq!(after, before + 1);
    assert_eq!(config.get("allowlist"), original.get("allowlist"));
    Ok(())
}


#[test]
fn the_reserved_rule_id_is_refused() -> TestResult {
    let refused = config_text(&checked_rules("[[rules]]\nid = \"ostyr-canary\"\nregex = '''x'''\n")?);
    assert!(matches!(
        refused,
        Err(ScanError::BadRules("the rules file uses the reserved canary rule id"))
    ));
    Ok(())
}


#[test]
fn the_report_limits_grow_by_the_canary_files() -> TestResult {
    let limits = Limits::default();
    let wide = widened_limits(&limits, THREE);
    assert_eq!(wide.max_findings, limits.max_findings + THREE);
    assert_eq!(wide.max_bytes, limits.max_bytes + THREE * REPORT_BYTES_PER_CANARY);
    assert_eq!((wide.kept_chars, wide.excerpt_chars), (limits.kept_chars, limits.excerpt_chars));
    let huge = Limits {
        max_findings: usize::MAX,
        ..limits
    };
    assert_eq!(widened_limits(&huge, 1).max_findings, usize::MAX);
    Ok(())
}


#[test]
fn a_missing_root_canary_is_a_blind_scan_and_a_missing_directory_is_named() -> TestResult {
    let summary = CopySummary {
        canary_total: THREE,
        canary_dirs: vec![PathBuf::from("a"), PathBuf::from("a/b")],
        ..CopySummary::default()
    };
    let canary = fixed();
    let root = Path::new("/srv/tree");
    let none = HashSet::new();
    assert!(matches!(check_canaries(&canary, &summary, root, &none), Err(ScanError::BlindScan)));
    let all: HashSet<String> = [shown("/srv/tree", ""), shown("/srv/tree", "a/"), shown("/srv/tree", "a/b/")].into();
    let clean = check_canaries(&canary, &summary, root, &all)?;
    assert_eq!((clean.dirs, clean.paths.len()), (0, 0));
    let partial: HashSet<String> = [shown("/srv/tree", ""), shown("/srv/tree", "a/")].into();
    let hidden = check_canaries(&canary, &summary, root, &partial)?;
    assert_eq!(hidden.dirs, 1);
    assert_eq!(hidden.paths, vec!["/srv/tree/a/b".to_string()]);
    let only_root: HashSet<String> = [shown("/srv/tree", "")].into();
    let all_hidden = check_canaries(&canary, &summary, root, &only_root)?;
    assert_eq!((all_hidden.dirs, all_hidden.paths.len()), (TWO, TWO));
    Ok(())
}
