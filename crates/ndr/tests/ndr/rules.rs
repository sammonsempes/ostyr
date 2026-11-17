use crate::support::{
    fixture, logging_on, quick_limits, write_rule, TestResult, BAD_RULE, EICAR_RULE, EXIT_OK, FAKE_YR, GROUP_UMASK, SECOND_RULE, SLEEP, STAT_YR,
    THREE, TWO,
};
use core_config::trusted_dir::TrustedDirError;
use ndr::error::NdrError;
use ndr::model::Limits;
use ndr::rules::{compile_args, describe, is_rule_file, list_rule_files, load_rules, read_rule, rule_files_from, swap_rules};
use rustix::fs::Mode;
use rustix::process::{getuid, umask};
use std::fs;
use std::io;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};


const MODE_GROUP_WRITABLE: u32 = 0o775;


#[test]
fn rule_files_are_recognised_by_extension() -> TestResult {
    assert!(is_rule_file(Path::new("a.yar")));
    assert!(is_rule_file(Path::new("a.yara")));
    assert!(!is_rule_file(Path::new("a.txt")));
    assert!(!is_rule_file(Path::new("yar")));
    Ok(())
}


#[test]
fn a_directory_of_rules_compiles_into_the_private_directory() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    write_rule(dir.path(), "b.yara", SECOND_RULE)?;
    write_rule(dir.path(), "notes.txt", "not a rule")?;
    let fake = fixture(FAKE_YR)?;
    let rules = load_rules(&fake.yr, dir.path(), &Limits::default())?;
    assert!(rules.compiled.is_file());
    assert!(rules.compiled.starts_with(fake.work_dir.path()));
    let workspace = rules.workspace.path().to_path_buf();
    assert!(workspace.join("rule-00000.yar").is_file());
    assert!(workspace.join("rule-00001.yar").is_file());
    assert!(!workspace.join("rule-00002.yar").exists());
    drop(rules);
    assert!(!workspace.exists());
    Ok(())
}


#[test]
fn the_compile_arguments_put_the_output_first_and_a_double_dash_before_the_files() -> TestResult {
    let args = compile_args(Path::new("/w/rules.yarc"), &[PathBuf::from("/w/a.yar"), PathBuf::from("/w/-b.yar")]);
    let text: Vec<String> = args.iter().map(|arg| arg.to_string_lossy().to_string()).collect();
    assert_eq!(text, vec!["compile", "--output", "/w/rules.yarc", "--", "/w/a.yar", "/w/-b.yar"]);
    Ok(())
}


#[test]
fn a_rule_that_does_not_compile_fails_the_whole_load_with_its_stderr() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    write_rule(dir.path(), "b.yar", BAD_RULE)?;
    let fake = fixture(FAKE_YR)?;
    let error = load_rules(&fake.yr, dir.path(), &Limits::default()).err().ok_or("the load must fail")?;
    assert!(matches!(
        error,
        NdrError::Compile {
            exited_ok: false,
            timed_out: false,
            cut: false,
            ..
        }
    ));
    assert!(describe(&error).contains("unknown identifier"));
    Ok(())
}


#[test]
fn a_compile_that_never_ends_is_killed_and_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    let fake = fixture(SLEEP)?;
    let error = load_rules(&fake.yr, dir.path(), &quick_limits()).err().ok_or("the load must fail")?;
    assert!(matches!(error, NdrError::Compile { timed_out: true, .. }));
    Ok(())
}


#[test]
fn a_compile_that_succeeds_without_an_output_file_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    let fake = fixture(EXIT_OK)?;
    let error = load_rules(&fake.yr, dir.path(), &Limits::default()).err().ok_or("the load must fail")?;
    assert!(matches!(error, NdrError::Compile { exited_ok: true, .. }));
    Ok(())
}


#[test]
fn a_failed_reload_keeps_the_current_rules_and_a_good_one_replaces_them() -> TestResult {
    assert!(logging_on());
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    let fake = fixture(FAKE_YR)?;
    let current = load_rules(&fake.yr, dir.path(), &Limits::default())?;
    let current_file = current.compiled.clone();
    write_rule(dir.path(), "b.yar", BAD_RULE)?;
    let kept = swap_rules(&fake.yr, current, dir.path(), &Limits::default());
    assert_eq!(kept.compiled, current_file);
    assert!(kept.compiled.is_file());
    fs::remove_file(dir.path().join("b.yar"))?;
    let replaced = swap_rules(&fake.yr, kept, dir.path(), &Limits::default());
    assert_ne!(replaced.compiled, current_file);
    assert!(!current_file.exists());
    assert!(replaced.compiled.is_file());
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
    let fake = fixture(FAKE_YR)?;
    assert!(matches!(load_rules(&fake.yr, dir.path(), &limits), Err(NdrError::RuleTooLarge { .. })));
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
fn loading_from_a_missing_directory_or_into_a_missing_work_dir_fails() -> TestResult {
    let dir = tempfile::tempdir()?;
    let fake = fixture(FAKE_YR)?;
    assert!(matches!(
        load_rules(&fake.yr, &dir.path().join("absent"), &Limits::default()),
        Err(NdrError::RulesDir { .. })
    ));
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    let missing_work = ndr::model::Yr {
        work_dir: dir.path().join("absent"),
        ..fake.yr.clone()
    };
    assert!(matches!(
        load_rules(&missing_work, dir.path(), &Limits::default()),
        Err(NdrError::WorkDir(_))
    ));
    Ok(())
}


#[test]
fn a_rule_copy_that_cannot_be_written_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    let result = ndr::rules::copy_rule(&dir.path().join("a.yar"), &dir.path().join("absent"), 0, Limits::default().max_rule_bytes);
    assert!(matches!(result, Err(NdrError::Workspace(_))));
    Ok(())
}


#[test]
fn the_rules_directory_and_its_copies_are_private_under_a_group_umask() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    write_rule(dir.path(), "b.yar", SECOND_RULE)?;
    let fake = fixture(STAT_YR)?;
    let previous = umask(Mode::from_raw_mode(GROUP_UMASK));
    let loaded = load_rules(&fake.yr, dir.path(), &Limits::default());
    umask(previous);
    let _rules = loaded?;
    let report = fs::read_to_string(fake.work_dir.path().join("report-compile"))?;
    let owner = getuid().as_raw();
    let expected = format!("700 {owner}\n600 {owner}\n600 {owner}\n");
    assert_eq!(report, expected);
    Ok(())
}


#[test]
fn a_work_directory_others_can_write_is_refused_before_any_run() -> TestResult {
    let dir = tempfile::tempdir()?;
    write_rule(dir.path(), "a.yar", EICAR_RULE)?;
    let fake = fixture(STAT_YR)?;
    fs::set_permissions(fake.work_dir.path(), fs::Permissions::from_mode(MODE_GROUP_WRITABLE))?;
    let result = load_rules(&fake.yr, dir.path(), &Limits::default());
    assert!(matches!(
        result,
        Err(NdrError::WorkDir(TrustedDirError::Refused(
            "work directory is writable by group or others"
        )))
    ));
    assert_eq!(fs::read_dir(fake.work_dir.path())?.count(), 0);
    Ok(())
}
