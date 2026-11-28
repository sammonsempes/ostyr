use crate::support::{
    field, fileinfo_line, fixture, logging_on, now, quick_limits, store, write_rule, Fixture, TestResult, EICAR, EICAR_RULE, EXIT_ONE_SCAN, FAKE_YR,
    FLOOD_SCAN, GROUP_UMASK, HANG_SCAN, SHA_A, SHA_B, SHA_C, SHA_D, STAT_YR, STDERR_TIMEOUT, TINY_LIMIT,
};
use ndr::error::NdrError;
use ndr::exec::Captured;
use ndr::model::{Limits, Scanned, Sighting, TickOutcome};
use ndr::rules::{load_rules, Rules};
use ndr::scan::{
    classify, file_total, is_identifier, log_bad_line, matched_rules, parse_matches, record_scan, scan_args, scan_group, scan_tick, Context,
};
use rustix::fs::Mode;
use rustix::process::{getuid, umask};
use std::fs;
use std::path::Path;


const ONE_FILE: usize = 1;


const FOUR_BYTES: u64 = 4;


const TWO_FILES: u64 = 2;


const THREE_FILES: u64 = 3;


const SMALL_OUTPUT: usize = 64;


const LONG_NAME: usize = 129;


const HIT_LINE: &[u8] = b"{\"path\":\"p\",\"rules\":[{\"identifier\":\"eicar\"}]}\n";


fn captured(bytes: &[u8], cut: bool, timed_out: bool, exited_ok: bool) -> Captured {
    Captured {
        bytes: bytes.to_vec(),
        cut,
        timed_out,
        exited_ok,
    }
}


fn sighting() -> Sighting {
    Sighting {
        sha256: SHA_A.to_string(),
        src_ip: None,
        dest_ip: None,
    }
}


fn setup(script: &str) -> Result<(Fixture, Rules), Box<dyn std::error::Error>> {
    let rules_dir = tempfile::tempdir()?;
    write_rule(rules_dir.path(), "a.yar", EICAR_RULE)?;
    let fake = fixture(script)?;
    let rules = load_rules(&fake.yr, rules_dir.path(), &Limits::default())?;
    Ok((fake, rules))
}


const TWO_DEFERRED: u64 = 2;


const FLOOD_LINES: usize = 100_000;


const LINE_CAP: usize = 500;


#[test]
fn the_scan_arguments_are_the_ones_the_fake_expects() -> TestResult {
    let args = scan_args(Path::new("/w/rules.yarc"), Path::new("/w/copy"));
    let text: Vec<String> = args.iter().map(|arg| arg.to_string_lossy().to_string()).collect();
    assert_eq!(
        text,
        vec![
            "scan",
            "--compiled-rules",
            "--output-format",
            "ndjson",
            "--threads",
            "1",
            "--no-mmap",
            "--disable-console-logs",
            "--disable-warnings",
            "--",
            "/w/rules.yarc",
            "/w/copy"
        ]
    );
    Ok(())
}


#[test]
fn a_match_a_miss_an_oversized_and_a_missing_file_are_each_counted() -> TestResult {
    let (fake, rules) = setup(FAKE_YR)?;
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
    let wide = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &Limits::default(), now());
    assert_eq!(wide.events.len() as u64, TWO_FILES);
    assert_eq!(
        (wide.counts.scanned, wide.counts.matched, wide.counts.missing, wide.counts.malformed),
        (THREE_FILES, TWO_FILES, 1, 1)
    );
    assert_eq!(wide.counts.lines, lines.len() as u64);
    let narrow = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &limits, now());
    assert!(narrow.events.is_empty());
    assert_eq!((narrow.counts.too_large, narrow.counts.scanned), (TWO_FILES, 1));
    let json = serde_json::to_value(wide.events.first().ok_or("an event")?)?;
    assert_eq!(field(&json, "/rule/name"), Some("eicar"));
    assert_eq!(field(&json, "/file/hash/sha256"), Some(SHA_A));
    assert_eq!(field(&json, "/destination/ip"), Some("10.0.0.2"));
    assert!(!json.to_string().contains("EICAR-STANDARD"));
    Ok(())
}


#[test]
fn the_private_copies_are_removed_after_every_scan() -> TestResult {
    let (fake, rules) = setup(FAKE_YR)?;
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, EICAR)?;
    let lines = [fileinfo_line(SHA_A)];
    scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &Limits::default(), now());
    let left = fs::read_dir(rules.workspace.path())?.count();
    assert_eq!(left, TWO_FILES as usize);
    Ok(())
}


#[test]
fn a_symlink_in_the_filestore_is_refused_and_counted() -> TestResult {
    let (fake, rules) = setup(FAKE_YR)?;
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    fs::write(outside.path().join("shadow"), EICAR)?;
    fs::create_dir(root.path().join("aa"))?;
    std::os::unix::fs::symlink(outside.path().join("shadow"), root.path().join("aa").join(SHA_A))?;
    let lines = [fileinfo_line(SHA_A)];
    let outcome = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &Limits::default(), now());
    assert_eq!((outcome.counts.refused, outcome.counts.scanned), (1, 0));
    assert!(outcome.events.is_empty());
    Ok(())
}


#[test]
fn files_beyond_the_tick_cap_are_deferred_and_lines_beyond_the_line_cap_are_not_read() -> TestResult {
    let (fake, rules) = setup(FAKE_YR)?;
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, EICAR)?;
    store(root.path(), SHA_B, EICAR)?;
    let lines = [fileinfo_line(SHA_A), fileinfo_line(SHA_B)];
    let capped = Limits {
        max_files_per_tick: ONE_FILE,
        ..Limits::default()
    };
    let outcome = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &capped, now());
    assert_eq!((outcome.counts.scanned, outcome.counts.deferred, outcome.events.len()), (1, 1, 1));
    let few_lines = Limits {
        max_lines_per_tick: ONE_FILE,
        ..Limits::default()
    };
    let short = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &few_lines, now());
    assert_eq!((short.counts.lines, short.counts.scanned), (1, 1));
    Ok(())
}


#[test]
fn deferred_hashes_are_returned_in_hash_order() -> TestResult {
    let (fake, rules) = setup(FAKE_YR)?;
    let root = tempfile::tempdir()?;
    [SHA_A, SHA_B, SHA_C].iter().try_for_each(|sha| store(root.path(), sha, EICAR))?;
    let lines = [SHA_C, SHA_A, SHA_B].map(fileinfo_line);
    let capped = Limits {
        max_files_per_tick: ONE_FILE,
        ..Limits::default()
    };
    let outcome = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &capped, now());
    assert_eq!((outcome.counts.scanned, outcome.counts.deferred), (1, TWO_DEFERRED));
    assert_eq!(outcome.deferred_hashes, vec![SHA_B.to_string(), SHA_C.to_string()]);
    assert_eq!(outcome.deferred_hashes.len() as u64, outcome.counts.deferred);
    Ok(())
}


#[test]
fn deferred_hashes_are_bounded_by_the_line_cap() -> TestResult {
    let (fake, rules) = setup(FAKE_YR)?;
    let root = tempfile::tempdir()?;
    let lines: Vec<String> = (0..FLOOD_LINES).map(|i| fileinfo_line(&format!("{i:064x}"))).collect();
    let capped = Limits {
        max_files_per_tick: ONE_FILE,
        max_lines_per_tick: LINE_CAP,
        ..Limits::default()
    };
    let outcome = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &capped, now());
    assert_eq!(outcome.deferred_hashes.len(), LINE_CAP - 1);
    assert_eq!(outcome.counts.lines, LINE_CAP as u64);
    Ok(())
}


#[test]
fn a_scan_that_never_ends_is_killed_and_counted_timed_out() -> TestResult {
    let (fake, rules) = setup(HANG_SCAN)?;
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, EICAR)?;
    let lines = [fileinfo_line(SHA_A)];
    let outcome = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &quick_limits(), now());
    assert_eq!((outcome.counts.timed_out, outcome.counts.scanned, outcome.counts.matched), (1, 0, 0));
    assert!(outcome.events.is_empty());
    Ok(())
}


#[test]
fn an_endless_output_is_cut_at_the_bound_and_counted() -> TestResult {
    let (fake, rules) = setup(FLOOD_SCAN)?;
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, EICAR)?;
    let lines = [fileinfo_line(SHA_A)];
    let limits = Limits {
        max_output_bytes: SMALL_OUTPUT,
        ..Limits::default()
    };
    let outcome = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &limits, now());
    assert_eq!((outcome.counts.output_cut, outcome.counts.scanned, outcome.counts.failed), (1, 0, 0));
    assert_eq!(file_total(&outcome), 1);
    Ok(())
}


#[test]
fn an_error_line_or_a_failing_exit_is_counted_failed_never_as_a_clean_scan() -> TestResult {
    assert!(logging_on());
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, EICAR)?;
    let lines = [fileinfo_line(SHA_A)];
    let outcomes = [STDERR_TIMEOUT, EXIT_ONE_SCAN]
        .into_iter()
        .map(|script| -> Result<TickOutcome, Box<dyn std::error::Error>> {
            let (fake, rules) = setup(script)?;
            Ok(scan_tick(
                &fake.yr,
                &rules,
                root.path(),
                lines.iter().map(String::as_str),
                &Limits::default(),
                now(),
            ))
        });
    outcomes
        .map(|result| -> TestResult {
            let outcome = result?;
            assert_eq!((outcome.counts.failed, outcome.counts.scanned, outcome.counts.matched), (1, 0, 0));
            Ok(())
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(())
}


#[test]
fn a_program_that_cannot_run_is_counted_run_refused() -> TestResult {
    assert!(logging_on());
    let (mut fake, rules) = setup(FAKE_YR)?;
    fake.yr.program = fake.program_dir.join("absent");
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, EICAR)?;
    let lines = [fileinfo_line(SHA_A)];
    let outcome = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &Limits::default(), now());
    assert_eq!((outcome.counts.run_refused, outcome.counts.failed, outcome.counts.scanned), (1, 0, 0));
    Ok(())
}


#[test]
fn matched_rules_scans_a_private_copy_of_the_content() -> TestResult {
    let (fake, rules) = setup(FAKE_YR)?;
    assert_eq!(
        matched_rules(&fake.yr, &rules, EICAR, &Limits::default())?,
        Scanned::Names(vec!["eicar".to_string()])
    );
    assert_eq!(
        matched_rules(&fake.yr, &rules, b"benign", &Limits::default())?,
        Scanned::Names(Vec::new())
    );
    let gone = Rules {
        compiled: rules.compiled.clone(),
        workspace: tempfile::tempdir()?,
    };
    let absent = gone.workspace.path().to_path_buf();
    fs::remove_dir_all(&absent)?;
    assert!(matches!(
        matched_rules(&fake.yr, &gone, EICAR, &Limits::default()),
        Err(NdrError::Workspace(_))
    ));
    Ok(())
}


#[test]
fn identifiers_are_ascii_and_bounded() -> TestResult {
    assert!(is_identifier("eicar_2"));
    assert!(!is_identifier(""));
    assert!(!is_identifier("a b"));
    assert!(!is_identifier("rul\u{e9}"));
    assert!(!is_identifier(&"a".repeat(LONG_NAME)));
    Ok(())
}


#[test]
fn parse_matches_accepts_result_lines_only() -> TestResult {
    assert_eq!(parse_matches(b"").ok_or("none")?, Vec::<String>::new());
    assert_eq!(parse_matches(HIT_LINE).ok_or("none")?, vec!["eicar".to_string()]);
    assert_eq!(parse_matches(b"{\"path\":\"p\",\"rules\":[]}\n").ok_or("none")?, Vec::<String>::new());
    assert!(parse_matches(b"error: boom\n").is_none());
    assert!(parse_matches(b"{\"path\":\"p\",\"rules\":[{\"identifier\":\"bad name\"}]}\n").is_none());
    assert!(parse_matches(b"{\"path\":\"p\"}\n").is_none());
    Ok(())
}


#[test]
fn a_bad_line_is_logged_by_class() -> TestResult {
    assert!(logging_on());
    let error = serde_json::from_slice::<serde_json::Value>(b"{").err().ok_or("a parse error")?;
    log_bad_line(&error);
    Ok(())
}


#[test]
fn the_verdict_order_is_deadline_then_bound_then_exit_then_output() -> TestResult {
    assert_eq!(classify(&captured(HIT_LINE, true, true, true)), Scanned::TimedOut);
    assert_eq!(classify(&captured(HIT_LINE, true, false, true)), Scanned::OutputCut);
    assert_eq!(classify(&captured(HIT_LINE, false, false, false)), Scanned::Failed);
    assert_eq!(classify(&captured(b"error: x\n", false, false, true)), Scanned::Failed);
    assert_eq!(
        classify(&captured(HIT_LINE, false, false, true)),
        Scanned::Names(vec!["eicar".to_string()])
    );
    Ok(())
}


#[test]
fn a_spawn_failure_is_counted_run_refused_apart_from_failed() -> TestResult {
    assert!(logging_on());
    let mut outcome = TickOutcome::default();
    let failure = NdrError::Spawn(std::io::Error::other("injected"));
    record_scan(&mut outcome, Err(failure), &[sighting()], FOUR_BYTES, now());
    assert_eq!((outcome.counts.run_refused, outcome.counts.failed, file_total(&outcome)), (1, 0, 1));
    Ok(())
}


#[test]
fn a_filestore_that_cannot_be_opened_is_counted_failed() -> TestResult {
    assert!(logging_on());
    let (fake, rules) = setup(FAKE_YR)?;
    let root = tempfile::tempdir()?;
    let limits = Limits {
        max_file_bytes: TINY_LIMIT,
        ..Limits::default()
    };
    let mut outcome = TickOutcome::default();
    let absent = root.path().join("absent");
    let context = Context {
        yr: &fake.yr,
        rules: &rules,
        root: &absent,
        limits: &limits,
    };
    scan_group(&context, SHA_A, &[sighting()], now(), &mut outcome);
    assert_eq!(outcome.counts.failed, 1);
    Ok(())
}


#[test]
fn a_hash_named_by_many_lines_is_scanned_once_and_every_line_gets_its_event() -> TestResult {
    let (fake, rules) = setup(FAKE_YR)?;
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, EICAR)?;
    let lines = [fileinfo_line(SHA_A), fileinfo_line(SHA_A), fileinfo_line(SHA_A)];
    let outcome = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &Limits::default(), now());
    assert_eq!(
        (outcome.counts.scanned, outcome.counts.matched, outcome.counts.lines),
        (1, 1, THREE_FILES)
    );
    assert_eq!(outcome.events.len() as u64, THREE_FILES);
    assert_eq!(file_total(&outcome), 1);
    Ok(())
}


#[test]
fn the_lines_kept_per_hash_are_capped_and_the_rest_counted() -> TestResult {
    let (fake, rules) = setup(FAKE_YR)?;
    let root = tempfile::tempdir()?;
    store(root.path(), SHA_A, EICAR)?;
    let lines = [fileinfo_line(SHA_A), fileinfo_line(SHA_A), fileinfo_line(SHA_A)];
    let limits = Limits {
        max_sightings_per_file: ONE_FILE,
        ..Limits::default()
    };
    let outcome = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &limits, now());
    assert_eq!(
        (outcome.counts.scanned, outcome.counts.sightings_omitted, outcome.events.len() as u64),
        (1, TWO_FILES, 1)
    );
    Ok(())
}


#[test]
fn a_hard_link_in_the_filestore_is_refused_and_counted() -> TestResult {
    let (fake, rules) = setup(FAKE_YR)?;
    let root = tempfile::tempdir()?;
    let outside = tempfile::tempdir()?;
    fs::write(outside.path().join("shadow"), EICAR)?;
    fs::create_dir(root.path().join("aa"))?;
    fs::hard_link(outside.path().join("shadow"), root.path().join("aa").join(SHA_A))?;
    let lines = [fileinfo_line(SHA_A)];
    let outcome = scan_tick(&fake.yr, &rules, root.path(), lines.iter().map(String::as_str), &Limits::default(), now());
    assert_eq!((outcome.counts.refused, outcome.counts.scanned), (1, 0));
    assert!(outcome.events.is_empty());
    Ok(())
}


#[test]
fn the_scan_copy_is_private_under_a_group_umask() -> TestResult {
    let (fake, rules) = setup(STAT_YR)?;
    let previous = umask(Mode::from_raw_mode(GROUP_UMASK));
    let scanned = matched_rules(&fake.yr, &rules, EICAR, &Limits::default());
    umask(previous);
    scanned?;
    let report = fs::read_to_string(fake.work_dir.path().join("report-scan"))?;
    let owner = getuid().as_raw();
    assert_eq!(report, format!("700 {owner}\n600 {owner}\n"));
    Ok(())
}
