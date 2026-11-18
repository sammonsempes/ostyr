#![cfg(unix)]
use attack_surface::error::{ResultsError, RunError, ScanFailure};
use attack_surface::model::{Counts, Found, Limits, Outcome, ScanReport, Scope, ScopeKind, TargetReport};
use attack_surface::run::{check_run_total, outcome_of, plan_target, run_target, scan_scope, scan_scope_until, summary_line, Plan};
use attack_surface::scope::parse_scope;
use net_topology::model::RunFailure;
use std::cell::Cell;
use std::error::Error;
use std::io::Error as IoError;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;
use types::TestResult;


#[path = "support/types.rs"]
mod types;


const SHORT_CAP: u64 = 100;


const SSH: u16 = 22;


const THREE: usize = 3;


const TWO: usize = 2;


const V4_OVER: u128 = 98_304;


const V6_OVER: u128 = 512;


const CODE_TWO: i32 = 2;


const READ_NINE: u64 = 9;


const EXIT_ONE: i32 = 1;


const DEADLINE_SECONDS: u64 = 5;


const GENEROUS_SECONDS: u64 = 60;


const EXTERNAL_TWO: &str = "kind: external
rate_per_second: 100
ports: [22]
targets:
  - value: 8.8.8.0/24
    ownership: {method: attestation, reference: TICKET-1}
  - value: 9.9.9.0/24
    ownership: {method: attestation, reference: TICKET-2}
";


fn scope_of(text: &str) -> Result<Scope, Box<dyn Error>> {
    let mut bytes = text.as_bytes();
    Ok(parse_scope(&mut bytes, "scope.yaml")?)
}


fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures").join(name)
}


fn missing() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/no-such-program")
}


fn generous() -> Duration {
    Duration::from_secs(GENEROUS_SECONDS)
}


fn found(text: &str, port: u16) -> Result<Found, Box<dyn Error>> {
    Ok(Found {
        ip: text.parse::<IpAddr>()?,
        port,
    })
}


fn outcome_at(report: &ScanReport, index: usize) -> Option<&Outcome> {
    report.targets.iter().find(|target| target.index == index).map(|target| &target.outcome)
}


#[test]
fn only_in_scope_results_are_kept_and_the_rest_counted() -> TestResult {
    let scope = scope_of(EXTERNAL_TWO)?;
    let report = scan_scope(&fixture("ok.sh"), &scope, &Limits::default(), generous(), generous())?;
    assert_eq!(report.found, vec![found("8.8.8.8", SSH)?, found("9.9.9.9", SSH)?]);
    assert_eq!(report.targets.len(), TWO);
    let expected = Outcome::Scanned {
        kept: TWO,
        counts: Counts {
            out_of_scope: TWO,
            malformed: 1,
            ..Counts::default()
        },
    };
    assert_eq!(outcome_at(&report, 0), Some(&expected));
    assert_eq!(
        summary_line(&report),
        "2 targets: 2 scanned, 0 ownership_unverified, 0 too_wide, 0 deferred, 0 failed"
    );
    Ok(())
}


#[test]
fn a_wrongly_typed_field_never_reaches_any_text_of_the_report() -> TestResult {
    let scope = scope_of(EXTERNAL_TWO)?;
    let report = scan_scope(&fixture("ok.sh"), &scope, &Limits::default(), generous(), generous())?;
    let debug = format!("{report:?}");
    assert!(!debug.contains("MARKER"));
    let failure = ScanFailure::from(ResultsError::Read(IoError::other("TYPED-MARKER")));
    assert_eq!(failure, ScanFailure::Unavailable);
    assert!(!format!("{failure} {failure:?}").contains("MARKER"));
    assert!(failure.source().is_none());
    Ok(())
}


#[test]
fn a_target_that_times_out_is_named_and_the_next_one_still_runs() -> TestResult {
    let scope = scope_of(EXTERNAL_TWO)?;
    let report = scan_scope(
        &fixture("sleep.sh"),
        &scope,
        &Limits::default(),
        Duration::from_secs(DEADLINE_SECONDS),
        generous(),
    )?;
    assert_eq!(outcome_at(&report, 0), Some(&Outcome::Failed(ScanFailure::Timeout)));
    assert!(matches!(outcome_at(&report, 1), Some(Outcome::Scanned { kept: 1, .. })));
    assert_eq!(report.found, vec![found("9.9.9.9", SSH)?]);
    assert_eq!(
        summary_line(&report),
        "2 targets: 1 scanned, 0 ownership_unverified, 0 too_wide, 0 deferred, 1 failed"
    );
    Ok(())
}


#[test]
fn an_output_over_the_cap_is_oversized() -> TestResult {
    let scope = scope_of(EXTERNAL_TWO)?;
    let limits = Limits {
        max_bytes: SHORT_CAP,
        ..Limits::default()
    };
    let report = scan_scope(&fixture("big.sh"), &scope, &limits, generous(), generous())?;
    assert_eq!(outcome_at(&report, 0), Some(&Outcome::Failed(ScanFailure::Oversized)));
    assert_eq!(outcome_at(&report, 1), Some(&Outcome::Failed(ScanFailure::Oversized)));
    assert!(report.found.is_empty());
    Ok(())
}


#[test]
fn an_exit_code_is_reported_without_the_stderr_text() -> TestResult {
    let scope = scope_of(EXTERNAL_TWO)?;
    let report = scan_scope(&fixture("fail.sh"), &scope, &Limits::default(), generous(), generous())?;
    let expected = Outcome::Failed(ScanFailure::Failed { code: Some(EXIT_ONE) });
    assert_eq!(outcome_at(&report, 0), Some(&expected));
    assert!(report.found.is_empty());
    assert!(!format!("{report:?}").contains("MARKER"));
    Ok(())
}


#[test]
fn an_unverified_or_too_wide_target_never_spawns_the_program() -> TestResult {
    let text = "kind: external
rate_per_second: 100
ports: [22]
targets:
  - value: 8.8.8.0/24
    ownership: {method: dns_txt, reference: TXT-1}
  - value: 2a00:1450::/64
    ownership: {method: attestation, reference: TICKET-2}
  - value: 9.9.9.0/24
    ownership: {method: attestation, reference: TICKET-3}
  - value: 9.9.9.0/24
    ownership: {method: dns_txt, reference: TXT-3}
";
    let scope = scope_of(text)?;
    let report = scan_scope(&missing(), &scope, &Limits::default(), generous(), generous())?;
    assert_eq!(report.targets.len(), THREE);
    assert_eq!(outcome_at(&report, 0), Some(&Outcome::TooWide));
    assert_eq!(outcome_at(&report, 1), Some(&Outcome::OwnershipUnverified));
    assert_eq!(outcome_at(&report, TWO), Some(&Outcome::OwnershipUnverified));
    assert_eq!(
        summary_line(&report),
        "3 targets: 0 scanned, 2 ownership_unverified, 1 too_wide, 0 deferred, 0 failed"
    );
    Ok(())
}


#[test]
fn an_attested_ipv6_range_up_to_a_slash_120_is_scanned() -> TestResult {
    let text = "kind: external
rate_per_second: 100
ports: [22]
targets:
  - value: 2a00:1450::/120
    ownership: {method: attestation, reference: TICKET-1}
";
    let scope = scope_of(text)?;
    let report = scan_scope(&missing(), &scope, &Limits::default(), generous(), generous())?;
    assert_eq!(outcome_at(&report, 0), Some(&Outcome::Failed(ScanFailure::Unavailable)));
    Ok(())
}


#[test]
fn an_internal_scope_scans_a_dns_txt_target() -> TestResult {
    let text = "kind: internal
rate_per_second: 100
ports: [22]
targets:
  - value: 192.168.1.0/24
    ownership: {method: dns_txt, reference: TXT-1}
";
    let scope = scope_of(text)?;
    let report = scan_scope(&fixture("ok.sh"), &scope, &Limits::default(), generous(), generous())?;
    assert!(matches!(outcome_at(&report, 0), Some(Outcome::Scanned { kept: 0, .. })));
    Ok(())
}


#[test]
fn a_run_over_the_total_is_refused_before_any_spawn() -> TestResult {
    let wide_v4 = "kind: internal
rate_per_second: 100
ports: [22]
targets:
  - value: 10.1.0.0/16
    ownership: {method: attestation, reference: TICKET-1}
  - value: 10.1.0.0/17
    ownership: {method: attestation, reference: TICKET-2}
";
    let result = scan_scope(&missing(), &scope_of(wide_v4)?, &Limits::default(), generous(), generous());
    assert!(matches!(result, Err(RunError::TooBroad { v4: V4_OVER, v6: 0, .. })));
    let wide_v6 = "kind: external
rate_per_second: 100
ports: [22]
targets:
  - value: 2a00:1450::/120
    ownership: {method: attestation, reference: TICKET-1}
  - value: 2a00:1450::100/120
    ownership: {method: attestation, reference: TICKET-2}
";
    let result_v6 = scan_scope(&missing(), &scope_of(wide_v6)?, &Limits::default(), generous(), generous());
    let error = result_v6.err().ok_or("accepted")?;
    assert!(matches!(error, RunError::TooBroad { v4: 0, v6: V6_OVER, .. }));
    assert!(error.to_string().contains("512"));
    Ok(())
}


#[test]
fn the_total_check_counts_the_planned_scans_only() -> TestResult {
    let net = "10.0.0.0/16".parse()?;
    let plans = vec![Plan::Scan(net), Plan::Skip(Outcome::TooWide)];
    assert!(check_run_total(&plans).is_ok());
    let more = vec![Plan::Scan(net), Plan::Scan("10.1.0.0/24".parse()?)];
    assert!(check_run_total(&more).is_err());
    Ok(())
}


#[test]
fn a_hand_built_scope_is_refused_before_any_spawn() -> TestResult {
    let hand = |kind: &str, target: &str| -> Result<Scope, Box<dyn Error>> {
        let mut scope = scope_of(EXTERNAL_TWO)?;
        scope.kind = if kind == "internal" { ScopeKind::Internal } else { ScopeKind::External };
        scope.targets = vec![target.to_string()];
        scope.attested = vec![target.to_string()];
        Ok(scope)
    };
    let cases = [
        ("external", "0.0.0.0/0"),
        ("external", "10.0.0.0/24"),
        ("external", "2a00:1450::/48"),
        ("external", "scan.example.com"),
        ("internal", "8.8.8.0/24"),
        ("external", "-host"),
    ];
    cases.iter().try_for_each(|(kind, target)| -> TestResult {
        let scope = hand(kind, target)?;
        let report = scan_scope(&missing(), &scope, &Limits::default(), generous(), generous())?;
        let outcome = outcome_at(&report, 0).ok_or("no outcome")?;
        let wide_v6 = matches!(outcome, Outcome::TooWide);
        assert!(*outcome == Outcome::Failed(ScanFailure::Refused) || wide_v6, "{target}: {outcome:?}");
        Ok(())
    })?;
    Ok(())
}


#[test]
fn an_unlisted_target_is_refused_by_the_runner() -> TestResult {
    let scope = scope_of(EXTERNAL_TWO)?;
    let result = run_target(&missing(), &scope, &Limits::default(), generous(), "7.7.7.0/24");
    assert_eq!(result.err(), Some(ScanFailure::Refused));
    Ok(())
}


#[test]
fn every_run_failure_has_a_fixed_category() -> TestResult {
    let table = [
        (RunFailure::TimedOut, ScanFailure::Timeout),
        (RunFailure::TooLarge, ScanFailure::Oversized),
        (
            RunFailure::Failed {
                code: Some(CODE_TWO),
                read: READ_NINE,
            },
            ScanFailure::Failed { code: Some(CODE_TWO) },
        ),
        (RunFailure::Failed { code: None, read: 0 }, ScanFailure::Failed { code: None }),
        (RunFailure::Refused, ScanFailure::Refused),
        (RunFailure::Spawn, ScanFailure::Unavailable),
        (RunFailure::Io, ScanFailure::Unavailable),
        (RunFailure::Unwaitable, ScanFailure::Unavailable),
    ];
    table
        .into_iter()
        .for_each(|(failure, expected)| assert_eq!(ScanFailure::from(failure), expected));
    Ok(())
}


#[test]
fn a_failed_result_has_no_found_entries() -> TestResult {
    let (outcome, kept) = outcome_of(Err(ScanFailure::Timeout));
    assert_eq!(outcome, Outcome::Failed(ScanFailure::Timeout));
    assert!(kept.is_empty());
    Ok(())
}


#[test]
fn an_unattested_hand_built_external_target_is_unverified() -> TestResult {
    let mut scope = scope_of(EXTERNAL_TWO)?;
    scope.attested = Vec::new();
    assert!(matches!(plan_target(&scope, "8.8.8.0/24"), Plan::Skip(Outcome::OwnershipUnverified)));
    let report = ScanReport {
        found: Vec::new(),
        targets: vec![TargetReport {
            index: 0,
            outcome: Outcome::TooWide,
        }],
    };
    assert_eq!(
        summary_line(&report),
        "1 targets: 0 scanned, 0 ownership_unverified, 1 too_wide, 0 deferred, 0 failed"
    );
    Ok(())
}


const THREE_TARGETS: &str = "kind: external
rate_per_second: 100
ports: [22]
targets:
  - value: 8.8.8.0/24
    ownership: {method: attestation, reference: TICKET-1}
  - value: 9.9.9.0/24
    ownership: {method: dns_txt, reference: TICKET-2}
  - value: 7.7.7.0/24
    ownership: {method: attestation, reference: TICKET-3}
";


#[test]
fn a_total_deadline_already_passed_defers_every_scan_and_never_spawns() -> TestResult {
    let scope = scope_of(THREE_TARGETS)?;
    let report = scan_scope(&missing(), &scope, &Limits::default(), generous(), Duration::ZERO)?;
    let outcomes = report
        .targets
        .iter()
        .map(|target| (target.index, target.outcome.clone()))
        .collect::<Vec<_>>();
    assert_eq!(
        outcomes,
        vec![(0, Outcome::Deferred), (1, Outcome::Deferred), (TWO, Outcome::OwnershipUnverified)]
    );
    assert!(report.found.is_empty());
    assert_eq!(
        summary_line(&report),
        "3 targets: 0 scanned, 1 ownership_unverified, 0 too_wide, 2 deferred, 0 failed"
    );
    Ok(())
}


#[test]
fn a_deadline_fired_by_the_first_run_defers_the_rest() -> TestResult {
    let asked = Cell::new(false);
    let scope = scope_of(THREE_TARGETS)?;
    let report = scan_scope_until(&fixture("ok.sh"), &scope, &Limits::default(), generous(), &|| asked.replace(true))?;
    let deferred = report
        .targets
        .iter()
        .map(|target| target.outcome == Outcome::Deferred)
        .collect::<Vec<_>>();
    assert_eq!(deferred, vec![false, true, false]);
    assert_eq!(report.found, vec![found("8.8.8.8", SSH)?, found("9.9.9.9", SSH)?]);
    Ok(())
}
