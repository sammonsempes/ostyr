use crate::support::{
    field, fileinfo_line, logging_on, now, quick_limits, store, write_rule, TestResult, EICAR, EICAR_RULE, SHA_A, SHA_B, SHA_C, SHA_D, SLOW_RULE,
    TINY_LIMIT,
};
use ndr::model::{Limits, Sighting, TickOutcome};
use ndr::rules::load_rules;
use ndr::scan::{file_total, record_scan, scan_sighting, scan_tick};
use std::fs;
use yara_x::errors::ScanError;


const ONE_FILE: usize = 1;


const FOUR_BYTES: u64 = 4;


const TWO_FILES: u64 = 2;


const THREE_FILES: u64 = 3;


#[test]
fn a_match_a_miss_an_oversized_and_a_missing_file_are_each_counted() -> TestResult {
    let rules_dir = tempfile::tempdir()?;
    write_rule(rules_dir.path(), "a.yar", EICAR_RULE)?;
    let rules = load_rules(rules_dir.path(), &Limits::default())?;
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, EICAR)?;
    store(root.path(), SHA_B, b"benign")?;
    store(root.path(), SHA_C, EICAR)?;
    let lines = [
        fileinfo_line(SHA_A),
        fileinfo_line(SHA_B),
        fileinfo_line(SHA_C),
        fileinfo_line(SHA_D),
        "{\"event_type\":\"dns\"}".to_string(),
        "\"fileinfo\" broken".to_string(),
    ];
    let limits = Limits {
        max_file_bytes: EICAR.len() as u64 - 1,
        ..Limits::default()
    };
    let wide = scan_tick(&rules, root.path(), lines.iter().map(String::as_str), &Limits::default(), now());
    assert_eq!(wide.events.len() as u64, TWO_FILES);
    assert_eq!(
        (wide.counts.scanned, wide.counts.matched, wide.counts.missing, wide.counts.malformed),
        (THREE_FILES, TWO_FILES, 1, 1)
    );
    assert_eq!(wide.counts.lines, lines.len() as u64);
    let narrow = scan_tick(&rules, root.path(), lines.iter().map(String::as_str), &limits, now());
    assert!(narrow.events.is_empty());
    assert_eq!((narrow.counts.too_large, narrow.counts.scanned), (TWO_FILES, 1));
    let json = serde_json::to_value(wide.events.first().ok_or("an event")?)?;
    assert_eq!(field(&json, "/rule/name"), Some("eicar"));
    assert_eq!(field(&json, "/file/hash/sha256"), Some(SHA_A));
    assert_eq!(field(&json, "/destination/ip"), Some("10.0.0.2"));
    assert!(!json.to_string().contains("EICAR-STANDARD"));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_symlink_in_the_filestore_is_refused_and_counted() -> TestResult {
    let rules_dir = tempfile::tempdir()?;
    write_rule(rules_dir.path(), "a.yar", "rule anything { condition: true }")?;
    let rules = load_rules(rules_dir.path(), &Limits::default())?;
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    fs::write(outside.path().join("shadow"), b"root:x")?;
    fs::create_dir(root.path().join("aa"))?;
    std::os::unix::fs::symlink(outside.path().join("shadow"), root.path().join("aa").join(SHA_A))?;
    let lines = [fileinfo_line(SHA_A)];
    let outcome = scan_tick(&rules, root.path(), lines.iter().map(String::as_str), &Limits::default(), now());
    assert_eq!((outcome.counts.refused, outcome.counts.scanned), (1, 0));
    assert!(outcome.events.is_empty());
    Ok(())
}


#[test]
fn files_beyond_the_tick_cap_are_deferred_and_lines_beyond_the_line_cap_are_not_read() -> TestResult {
    let rules_dir = tempfile::tempdir()?;
    write_rule(rules_dir.path(), "a.yar", EICAR_RULE)?;
    let rules = load_rules(rules_dir.path(), &Limits::default())?;
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, EICAR)?;
    store(root.path(), SHA_B, EICAR)?;
    let lines = [fileinfo_line(SHA_A), fileinfo_line(SHA_B)];
    let capped = Limits {
        max_files_per_tick: ONE_FILE,
        ..Limits::default()
    };
    let outcome = scan_tick(&rules, root.path(), lines.iter().map(String::as_str), &capped, now());
    assert_eq!((outcome.counts.scanned, outcome.counts.deferred, outcome.events.len()), (1, 1, 1));
    let few_lines = Limits {
        max_lines_per_tick: ONE_FILE,
        ..Limits::default()
    };
    let short = scan_tick(&rules, root.path(), lines.iter().map(String::as_str), &few_lines, now());
    assert_eq!((short.counts.lines, short.counts.scanned), (1, 1));
    Ok(())
}


#[test]
fn a_slow_rule_hits_the_scan_timeout_and_is_counted() -> TestResult {
    let rules_dir = tempfile::tempdir()?;
    write_rule(rules_dir.path(), "slow.yar", SLOW_RULE)?;
    let rules = load_rules(rules_dir.path(), &Limits::default())?;
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, EICAR)?;
    let lines = [fileinfo_line(SHA_A)];
    let outcome = scan_tick(&rules, root.path(), lines.iter().map(String::as_str), &quick_limits(), now());
    assert_eq!((outcome.counts.timed_out, outcome.counts.scanned, outcome.counts.matched), (1, 0, 0));
    assert!(outcome.events.is_empty());
    Ok(())
}


#[test]
fn another_scan_failure_is_counted_failed() -> TestResult {
    assert!(logging_on());
    let sighting = Sighting {
        sha256: SHA_A.to_string(),
        src_ip: None,
        dest_ip: None,
    };
    let mut outcome = TickOutcome::default();
    let failure = ScanError::OpenError {
        path: "x".into(),
        err: std::io::Error::other("injected"),
    };
    record_scan(&mut outcome, Err(failure), &sighting, FOUR_BYTES, now());
    assert_eq!((outcome.counts.failed, file_total(&outcome)), (1, 1));
    Ok(())
}


#[test]
fn a_filestore_that_cannot_be_opened_is_counted_failed() -> TestResult {
    assert!(logging_on());
    let rules_dir = tempfile::tempdir()?;
    write_rule(rules_dir.path(), "a.yar", EICAR_RULE)?;
    let rules = load_rules(rules_dir.path(), &Limits::default())?;
    let root = tempfile::tempdir()?;
    let sighting = Sighting {
        sha256: SHA_A.to_string(),
        src_ip: None,
        dest_ip: None,
    };
    let limits = Limits {
        max_file_bytes: TINY_LIMIT,
        ..Limits::default()
    };
    let mut outcome = TickOutcome::default();
    scan_sighting(&rules, &root.path().join("absent"), &sighting, &limits, now(), &mut outcome);
    assert_eq!(outcome.counts.failed, 1);
    Ok(())
}
