mod common;


use common::types::TestResult;
use sla_report::error::RunError;
use sla_report::model::{Cadence, ErrorBudget, Period, Report, ReportDefinition, ReportFormat, ReportLimits, ReportTotals, SlaFigure, WriteOutcome};
use sla_report::report::default_report_limits;
use sla_report::run::{outcome_of_persist, period_stamp, render, report_file_name, run_due, write_once};
use sla_report::types::FiguresError;
use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::Path;


struct FailingWriter;


impl Write for FailingWriter {
    fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
        Err(io::Error::other("injected failure"))
    }

    fn flush(&mut self) -> io::Result<()> {
        Err(io::Error::other("injected failure"))
    }
}


const WEEK_1019: i64 = 1_792_368_000;


const WEEK_1026: i64 = 1_792_972_800;


const WEEK_1109: i64 = 1_794_182_400;


const NOW: i64 = 1_794_189_600;


const FIVE_HOURS: i64 = 18_000;


const OFFSET_MINUS_300: i32 = -300;


const OFFSET_PLUS_345: i32 = 345;


const PLUS_345_SECONDS: i64 = 20_700;


const OBJECTIVE: u32 = 999_000;


const BAD_OBJECTIVE: u32 = 2_000_000;


const BAD_OFFSET: i32 = 5;


const FIGURE_SECONDS: i64 = 100;


const ALLOWED_SECONDS: i64 = 10;


const FULL_PPM: u32 = 1_000_000;


const NINE: usize = 9;


const SIX: usize = 6;


const THREE: usize = 3;


const TWO: usize = 2;


const FORMAT_COUNT: usize = 2;


fn figure() -> SlaFigure {
    SlaFigure {
        up_seconds: FIGURE_SECONDS,
        down_seconds: 0,
        unknown_seconds: 0,
        excluded_seconds: 0,
        availability_ppm: Some(FULL_PPM),
        budget: ErrorBudget {
            allowed_seconds: ALLOWED_SECONDS,
            consumed_seconds: 0,
            remaining_seconds: ALLOWED_SECONDS,
            exhausted: false,
        },
        ignored: 0,
        method: "test".to_string(),
    }
}


fn definition(id: &str, services: &[&str], formats: &[ReportFormat]) -> ReportDefinition {
    ReportDefinition {
        id: id.to_string(),
        tenant: "acme".to_string(),
        title: "Weekly".to_string(),
        services: services.iter().map(|name| name.to_string()).collect(),
        cadence: Cadence::Weekly,
        utc_offset_minutes: 0,
        objective_ppm: OBJECTIVE,
        grace_seconds: 0,
        formats: formats.to_vec(),
    }
}


fn both() -> [ReportFormat; FORMAT_COUNT] {
    [ReportFormat::Csv, ReportFormat::Json]
}


fn state(ids: &[&str]) -> BTreeMap<String, i64> {
    ids.iter().map(|id| (id.to_string(), WEEK_1019)).collect()
}


fn count_files(dir: &Path) -> Result<usize, io::Error> {
    Ok(fs::read_dir(dir)?.count())
}


fn ok_figures(_service: &str, _period: &Period) -> Result<SlaFigure, FiguresError> {
    Ok(figure())
}


fn sample_report() -> Report {
    Report {
        tenant: "acme".to_string(),
        start: 0,
        end: 1,
        lines: Vec::new(),
        totals: ReportTotals::default(),
    }
}


#[test]
fn writes_every_format_of_every_due_period() -> TestResult {
    let dir = tempfile::tempdir()?;
    let definitions = [
        definition("weekly", &["web", "api"], &both()),
        definition("other", &["db"], &[ReportFormat::Csv]),
    ];
    let summary = run_due(
        &definitions,
        &ok_figures,
        dir.path(),
        &state(&["weekly", "other"]),
        NOW,
        &default_report_limits(),
    );
    assert_eq!((summary.written, summary.already_written, summary.failed), (NINE, 0, 0));
    assert_eq!(summary.last_done.get("weekly"), Some(&WEEK_1109));
    assert_eq!(summary.last_done.get("other"), Some(&WEEK_1109));
    assert_eq!(count_files(dir.path())?, NINE);
    let csv = fs::read_to_string(dir.path().join("weekly_20261026T000000Z.csv"))?;
    assert!(csv.starts_with("service,"));
    assert!(dir.path().join("weekly_20261102T000000Z.json").exists());
    Ok(())
}


#[test]
fn a_rerun_writes_nothing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let definitions = [
        definition("weekly", &["web", "api"], &both()),
        definition("other", &["db"], &[ReportFormat::Csv]),
    ];
    let input = state(&["weekly", "other"]);
    run_due(&definitions, &ok_figures, dir.path(), &input, NOW, &default_report_limits());
    let again = run_due(&definitions, &ok_figures, dir.path(), &input, NOW, &default_report_limits());
    assert_eq!((again.written, again.already_written, again.failed), (0, NINE, 0));
    assert_eq!(again.last_done.get("weekly"), Some(&WEEK_1109));
    assert_eq!(count_files(dir.path())?, NINE);
    Ok(())
}


#[test]
fn an_existing_csv_is_left_untouched() -> TestResult {
    let dir = tempfile::tempdir()?;
    let existing = dir.path().join("weekly_20261026T000000Z.csv");
    fs::write(&existing, b"mine")?;
    let definitions = [definition("weekly", &["web"], &both())];
    let summary = run_due(&definitions, &ok_figures, dir.path(), &state(&["weekly"]), NOW, &default_report_limits());
    assert_eq!((summary.written, summary.already_written, summary.failed), (SIX - 1, 1, 0));
    assert_eq!(fs::read(&existing)?, b"mine");
    assert!(dir.path().join("weekly_20261026T000000Z.json").exists());
    assert_eq!(count_files(dir.path())?, SIX);
    Ok(())
}


fn fails_on_second(_service: &str, period: &Period) -> Result<SlaFigure, FiguresError> {
    if period.start == WEEK_1026 {
        Err("figures unavailable".into())
    } else {
        Ok(figure())
    }
}


#[test]
fn a_failing_figures_call_stops_the_definition() -> TestResult {
    let dir = tempfile::tempdir()?;
    let definitions = [definition("weekly", &["web"], &both())];
    let summary = run_due(
        &definitions,
        &fails_on_second,
        dir.path(),
        &state(&["weekly"]),
        NOW,
        &default_report_limits(),
    );
    assert_eq!((summary.written, summary.already_written, summary.failed), (TWO, 0, 1));
    assert_eq!(summary.last_done.get("weekly"), Some(&WEEK_1026));
    assert_eq!(count_files(dir.path())?, TWO);
    Ok(())
}


#[test]
fn a_service_list_over_the_cap_is_a_counted_failure() -> TestResult {
    let dir = tempfile::tempdir()?;
    let limits = ReportLimits {
        max_services: 1,
        ..default_report_limits()
    };
    let definitions = [definition("weekly", &["web", "api"], &both())];
    let summary = run_due(&definitions, &ok_figures, dir.path(), &BTreeMap::new(), NOW, &limits);
    assert_eq!((summary.written, summary.failed), (0, 1));
    assert!(summary.last_done.is_empty());
    assert_eq!(count_files(dir.path())?, 0);
    Ok(())
}


#[test]
fn file_names_follow_the_offset() -> TestResult {
    assert_eq!(
        report_file_name("x", WEEK_1109 + FIVE_HOURS, ReportFormat::Csv)?,
        "x_20261109T050000Z.csv"
    );
    assert_eq!(
        report_file_name("x", WEEK_1109 - PLUS_345_SECONDS, ReportFormat::Json)?,
        "x_20261108T181500Z.json"
    );
    let dir = tempfile::tempdir()?;
    let minus = ReportDefinition {
        utc_offset_minutes: OFFSET_MINUS_300,
        ..definition("minus", &["web"], &[ReportFormat::Csv])
    };
    let plus = ReportDefinition {
        utc_offset_minutes: OFFSET_PLUS_345,
        ..definition("plus", &["web"], &[ReportFormat::Csv])
    };
    let summary = run_due(&[minus, plus], &ok_figures, dir.path(), &BTreeMap::new(), NOW, &default_report_limits());
    assert_eq!((summary.written, summary.failed), (TWO, 0));
    assert!(dir.path().join("minus_20261026T050000Z.csv").exists());
    assert!(dir.path().join("plus_20261101T181500Z.csv").exists());
    Ok(())
}


#[test]
fn pdf_and_bad_names_are_refused() -> TestResult {
    assert!(matches!(report_file_name("x", 0, ReportFormat::Pdf), Err(RunError::PdfNotSupported)));
    assert!(matches!(
        render(ReportFormat::Pdf, &sample_report(), Vec::new()),
        Err(RunError::PdfNotSupported)
    ));
    assert!(matches!(report_file_name("x", i64::MAX, ReportFormat::Csv), Err(RunError::Schedule(_))));
    assert!(period_stamp(i64::MAX).is_err());
    let dir = tempfile::tempdir()?;
    let definitions = [
        definition("weekly", &["web"], &[ReportFormat::Pdf]),
        definition("../evil", &["web"], &[ReportFormat::Csv]),
        ReportDefinition {
            utc_offset_minutes: BAD_OFFSET,
            ..definition("badoffset", &["web"], &[ReportFormat::Csv])
        },
    ];
    let summary = run_due(&definitions, &ok_figures, dir.path(), &BTreeMap::new(), NOW, &default_report_limits());
    assert_eq!((summary.written, summary.failed), (0, THREE));
    assert_eq!(count_files(dir.path())?, 0);
    Ok(())
}


#[test]
fn an_invalid_objective_is_a_counted_failure() -> TestResult {
    let dir = tempfile::tempdir()?;
    let bad = ReportDefinition {
        objective_ppm: BAD_OBJECTIVE,
        ..definition("weekly", &["web"], &[ReportFormat::Csv])
    };
    let summary = run_due(&[bad], &ok_figures, dir.path(), &BTreeMap::new(), NOW, &default_report_limits());
    assert_eq!((summary.written, summary.failed), (0, 1));
    Ok(())
}


#[test]
fn a_missing_directory_is_a_counted_failure() -> TestResult {
    let dir = tempfile::tempdir()?;
    let missing = dir.path().join("absent");
    let definitions = [definition("weekly", &["web"], &both())];
    let summary = run_due(&definitions, &ok_figures, &missing, &BTreeMap::new(), NOW, &default_report_limits());
    assert_eq!((summary.written, summary.failed), (0, 1));
    assert!(summary.last_done.is_empty());
    Ok(())
}


#[test]
fn nothing_due_keeps_the_previous_state() -> TestResult {
    let dir = tempfile::tempdir()?;
    let definitions = [definition("weekly", &["web"], &both())];
    let input = BTreeMap::from([("weekly".to_string(), WEEK_1109)]);
    let summary = run_due(&definitions, &ok_figures, dir.path(), &input, WEEK_1109 + 1, &default_report_limits());
    assert_eq!((summary.written, summary.failed), (0, 0));
    assert_eq!(summary.last_done.get("weekly"), Some(&WEEK_1109));
    Ok(())
}


#[test]
fn rendering_and_persisting_errors_are_kept() -> TestResult {
    assert!(matches!(
        render(ReportFormat::Csv, &sample_report(), FailingWriter),
        Err(RunError::Export(_))
    ));
    assert!(matches!(
        render(ReportFormat::Json, &sample_report(), FailingWriter),
        Err(RunError::Export(_))
    ));
    assert!(matches!(outcome_of_persist(Ok(())), Ok(WriteOutcome::Written)));
    let exists = io::Error::from(io::ErrorKind::AlreadyExists);
    assert!(matches!(outcome_of_persist(Err(exists)), Ok(WriteOutcome::AlreadyWritten)));
    let other = io::Error::other("disk");
    assert!(matches!(outcome_of_persist(Err(other)), Err(RunError::Io(_))));
    let dir = tempfile::tempdir()?;
    let first = write_once(dir.path(), "a.json", ReportFormat::Json, &sample_report())?;
    let second = write_once(dir.path(), "a.json", ReportFormat::Json, &sample_report())?;
    assert_eq!((first, second), (WriteOutcome::Written, WriteOutcome::AlreadyWritten));
    assert!(matches!(
        write_once(dir.path(), "b.pdf", ReportFormat::Pdf, &sample_report()),
        Err(RunError::PdfNotSupported)
    ));
    assert_eq!(count_files(dir.path())?, 1);
    Ok(())
}
