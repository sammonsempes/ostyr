use crate::support::{logging_on, quick_limits, write_rule, TestResult, BAD_RULE, EICAR, EICAR_RULE, SECOND_RULE, THREE, TWO};
use ndr::error::NdrError;
use ndr::model::Limits;
use ndr::rules::{describe, is_rule_file, list_rule_files, load_rules, read_rule, rule_files_from, swap_rules};
use ndr::scan::matched_rules;
use std::error::Error;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};


#[test]
fn rule_files_are_recognised_by_extension() -> TestResult {
    assert!(is_rule_file(Path::new("a.yar")));
    assert!(is_rule_file(Path::new("a.yara")));
    assert!(!is_rule_file(Path::new("a.txt")));
    assert!(!is_rule_file(Path::new("yar")));
    Ok(())
}


#[test]
fn a_directory_of_rules_compiles_and_matches() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    write_rule(dir.path(), "b.yara", SECOND_RULE)?;
    write_rule(dir.path(), "notes.txt", "not a rule")?;
    let rules = load_rules(dir.path(), &Limits::default())?;
    let mut names = matched_rules(&rules, EICAR, quick_limits().scan_timeout)?;
    names.sort();
    assert_eq!(names, vec!["eicar".to_string(), "marker".to_string()]);
    assert!(matched_rules(&rules, b"benign", quick_limits().scan_timeout)?.is_empty());
    Ok(())
}


#[test]
fn a_rule_that_does_not_compile_fails_the_whole_load_with_its_cause() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    write_rule(dir.path(), "b.yar", BAD_RULE)?;
    let error = load_rules(dir.path(), &Limits::default()).err().ok_or("the load must fail")?;
    assert!(matches!(error, NdrError::Compile { .. }));
    assert!(error.source().is_some());
    assert!(describe(&error).contains("does not compile: "));
    Ok(())
}


#[test]
fn a_failed_reload_keeps_the_current_rules_and_a_good_one_replaces_them() -> TestResult {
    assert!(logging_on());
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    let current = load_rules(dir.path(), &Limits::default())?;
    write_rule(dir.path(), "b.yar", BAD_RULE)?;
    let kept = swap_rules(current, dir.path(), &Limits::default());
    assert_eq!(matched_rules(&kept, EICAR, quick_limits().scan_timeout)?, vec!["eicar".to_string()]);
    fs::remove_file(dir.path().join("b.yar"))?;
    write_rule(dir.path(), "a.yar", "rule other { condition: false }")?;
    let replaced = swap_rules(kept, dir.path(), &Limits::default());
    assert!(matched_rules(&replaced, EICAR, quick_limits().scan_timeout)?.is_empty());
    Ok(())
}


#[test]
fn an_empty_or_missing_directory_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    assert!(matches!(list_rule_files(dir.path(), &Limits::default()), Err(NdrError::NoRules)));
    assert!(matches!(
        list_rule_files(&dir.path().join("absent"), &Limits::default()),
        Err(NdrError::RulesDir { .. })
    ));
    Ok(())
}


#[test]
fn more_rule_files_than_the_cap_is_refused_not_cut() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    write_rule(dir.path(), "b.yar", SECOND_RULE)?;
    write_rule(dir.path(), "c.yar", "rule third { condition: false }")?;
    let limits = Limits {
        max_rule_files: TWO,
        ..Limits::default()
    };
    assert!(matches!(
        list_rule_files(dir.path(), &limits),
        Err(NdrError::TooManyRuleFiles { max_files: TWO })
    ));
    let exact = Limits {
        max_rule_files: THREE,
        ..Limits::default()
    };
    assert_eq!(list_rule_files(dir.path(), &exact)?.len(), THREE);
    Ok(())
}


#[test]
fn a_listing_error_is_kept() -> TestResult {
    let entries = vec![Ok(PathBuf::from("a.yar")), Err(io::Error::other("injected listing failure"))];
    let error = rule_files_from(Box::new(entries.into_iter()), Path::new("rules"), &Limits::default()).err();
    assert!(matches!(error, Some(NdrError::RulesDir { .. })));
    Ok(())
}


#[test]
fn an_oversized_rule_file_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    let limits = Limits {
        max_rule_bytes: 1,
        ..Limits::default()
    };
    assert!(matches!(load_rules(dir.path(), &limits), Err(NdrError::RuleTooLarge { .. })));
    Ok(())
}


#[test]
fn an_unreadable_or_non_utf8_rule_file_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join("dir.yar"))?;
    assert!(matches!(
        read_rule(&dir.path().join("dir.yar"), THREE as u64),
        Err(NdrError::RuleRead { .. })
    ));
    assert!(matches!(
        read_rule(&dir.path().join("absent.yar"), THREE as u64),
        Err(NdrError::RuleRead { .. })
    ));
    fs::write(dir.path().join("bin.yar"), b"\xff\xfe")?;
    assert!(matches!(
        read_rule(&dir.path().join("bin.yar"), THREE as u64),
        Err(NdrError::RuleRead { .. })
    ));
    Ok(())
}


#[test]
fn a_cause_free_error_describes_itself_alone() -> TestResult {
    assert_eq!(describe(&NdrError::NoRules), "the rules directory holds no rule file");
    Ok(())
}


#[test]
fn loading_from_a_missing_directory_fails() -> TestResult {
    let dir = tempfile::tempdir()?;
    assert!(matches!(
        load_rules(&dir.path().join("absent"), &Limits::default()),
        Err(NdrError::RulesDir { .. })
    ));
    Ok(())
}
