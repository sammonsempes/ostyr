#[path = "common/types.rs"]
mod types;


use secret_scan::error::ReportError;
use secret_scan::model::{Limits, ScanScope, DEFAULT_EXCERPT_CHARS, DEFAULT_KEPT_CHARS, DEFAULT_MAX_BYTES, DEFAULT_MAX_FINDINGS};
use secret_scan::report::{parse_report, read_bounded};
use types::TestResult;


struct FailingReader;


impl std::io::Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("disk gone"))
    }
}


const SAMPLE: &[u8] = include_bytes!("fixtures/gitleaks-report.json");


const SAMPLE_FINDINGS: usize = 3;


const TINY_BYTES: usize = 16;


const TWO: usize = 2;


const FIVE: usize = 5;


const TEN: usize = 10;


const LONG_ARRAY: usize = 100_000;


const LINE_TWELVE: u64 = 12;


const LINE_THREE: u64 = 3;


const LINE_FOUR: u64 = 4;


fn scope_skipping(patterns: &[&str]) -> ScanScope {
    ScanScope {
        skipped_paths: patterns.iter().map(|pattern| (*pattern).to_string()).collect(),
    }
}


#[test]
fn real_report_is_parsed_and_masked() -> TestResult {
    let report = parse_report(SAMPLE, &Limits::default(), "acme", "repo-main", &ScanScope::default())?;
    assert_eq!(report.tenant, "acme");
    assert_eq!(report.scope_id, "repo-main");
    assert_eq!((report.malformed, report.skipped), (0, 0));
    assert_eq!(report.findings.len(), SAMPLE_FINDINGS);
    let first = report.findings.first().ok_or("no first finding")?;
    assert_eq!(first.file, "config/prod.env");
    assert_eq!((first.start_line, first.end_line), (LINE_TWELVE, LINE_TWELVE));
    assert_eq!(first.commit.as_deref(), Some("a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"));
    assert_eq!(first.rule_id, "aws-access-token");
    assert_eq!(first.excerpt, "aws_key = \\\"AKIA********\\\"");
    let second = report.findings.get(1).ok_or("no second finding")?;
    assert_eq!(second.commit, None);
    assert_eq!((second.start_line, second.end_line), (LINE_THREE, LINE_FOUR));
    assert_eq!(second.excerpt, "api_key: s3cr********");
    Ok(())
}


#[test]
fn skipped_paths_are_dropped_and_counted() -> TestResult {
    let report = parse_report(
        SAMPLE,
        &Limits::default(),
        "acme",
        "repo-main",
        &scope_skipping(&["vendor/**", "nothing/*"]),
    )?;
    assert_eq!(report.findings.len(), TWO);
    assert_eq!(report.skipped, 1);
    assert!(report.findings.iter().all(|finding| !finding.file.starts_with("vendor")));
    Ok(())
}


#[test]
fn invalid_pattern_is_an_error() -> TestResult {
    let result = parse_report(SAMPLE, &Limits::default(), "acme", "s", &scope_skipping(&["[unclosed"]));
    assert!(matches!(result, Err(ReportError::InvalidPattern(_))));
    Ok(())
}


#[test]
fn malformed_entries_are_counted_and_skipped() -> TestResult {
    let report = parse_report(
        br#"[{"File":"a","StartLine":"x","EndLine":1,"RuleID":"r","Secret":"topsecretvalue"}, 7, {"File":"b","StartLine":1,"EndLine":1,"RuleID":"r"}]"#.as_slice(),
        &Limits::default(),
        "acme",
        "s",
        &ScanScope::default(),
    )?;
    assert_eq!(report.malformed, TWO);
    assert_eq!(report.findings.len(), 1);
    let only = report.findings.first().ok_or("no finding")?;
    assert_eq!(only.excerpt, "********");
    Ok(())
}


#[test]
fn secret_shorter_than_the_prefix_is_fully_masked() -> TestResult {
    let report = parse_report(
        br#"[{"File":"a","StartLine":1,"EndLine":1,"RuleID":"r","Match":"pin=123","Secret":"123"}]"#.as_slice(),
        &Limits::default(),
        "acme",
        "s",
        &ScanScope::default(),
    )?;
    let only = report.findings.first().ok_or("no finding")?;
    assert_eq!(only.excerpt, "pin=********");
    Ok(())
}


#[test]
fn oversized_report_is_refused() -> TestResult {
    let limits = Limits {
        max_bytes: TINY_BYTES,
        ..Limits::default()
    };
    let result = parse_report(SAMPLE, &limits, "acme", "s", &ScanScope::default());
    assert!(matches!(result, Err(ReportError::TooLarge { max: TINY_BYTES })));
    Ok(())
}


#[test]
fn report_at_the_byte_limit_is_accepted() -> TestResult {
    let limits = Limits {
        max_bytes: TWO,
        ..Limits::default()
    };
    let report = parse_report(b"[]".as_slice(), &limits, "acme", "s", &ScanScope::default())?;
    assert!(report.findings.is_empty());
    Ok(())
}


#[test]
fn too_many_findings_is_refused() -> TestResult {
    let limits = Limits {
        max_findings: TWO,
        ..Limits::default()
    };
    let result = parse_report(SAMPLE, &limits, "acme", "s", &ScanScope::default());
    assert!(matches!(result, Err(ReportError::TooManyFindings { max: TWO })));
    Ok(())
}


#[test]
fn non_array_reports_are_refused_without_echoing_content() -> TestResult {
    ["{}", "\"TOPSECRET\"", "[1,", ""].iter().for_each(|body| {
        let result = parse_report(body.as_bytes(), &Limits::default(), "acme", "s", &ScanScope::default());
        assert!(matches!(result, Err(ReportError::NotAnArray { .. })));
        assert!(!format!("{result:?}").contains("TOPSECRET"));
    });
    Ok(())
}


#[test]
fn read_failure_is_an_error() -> TestResult {
    let result = read_bounded(FailingReader, TEN);
    assert!(matches!(result, Err(ReportError::Read(_))));
    let message = result.err().map(|error| error.to_string());
    assert_eq!(message.as_deref(), Some("cannot read the report: disk gone"));
    Ok(())
}


#[test]
fn error_messages_are_readable() -> TestResult {
    assert_eq!(ReportError::TooLarge { max: FIVE }.to_string(), "report is above the 5 byte limit");
    assert_eq!(
        ReportError::TooManyFindings { max: FIVE }.to_string(),
        "report holds more than 5 findings"
    );
    assert_eq!(
        ReportError::NotAnArray { line: 1, column: TWO }.to_string(),
        "report is not a JSON array (line 1, column 2)"
    );
    Ok(())
}


#[test]
fn text_fields_are_escaped() -> TestResult {
    let report = parse_report(
        br#"[{"File":"a\nb","StartLine":1,"EndLine":1,"RuleID":"r\u0007","Commit":"c\n"}]"#.as_slice(),
        &Limits::default(),
        "acme",
        "s",
        &ScanScope::default(),
    )?;
    let only = report.findings.first().ok_or("no finding")?;
    assert_eq!(only.file, "a\\nb");
    assert_eq!(only.rule_id, "r\\u{7}");
    assert_eq!(only.commit.as_deref(), Some("c\\n"));
    Ok(())
}


#[test]
fn default_limits_are_the_declared_ones() -> TestResult {
    let limits = Limits::default();
    assert_eq!(limits.max_bytes, DEFAULT_MAX_BYTES);
    assert_eq!(limits.max_findings, DEFAULT_MAX_FINDINGS);
    assert_eq!(limits.kept_chars, DEFAULT_KEPT_CHARS);
    assert_eq!(limits.excerpt_chars, DEFAULT_EXCERPT_CHARS);
    Ok(())
}


#[test]
fn long_array_is_refused_by_count_with_a_small_cap() -> TestResult {
    let limits = Limits {
        max_findings: TWO,
        ..Limits::default()
    };
    let body = format!("[{}0]", "0,".repeat(LONG_ARRAY));
    let result = parse_report(body.as_bytes(), &limits, "acme", "s", &ScanScope::default());
    assert!(matches!(result, Err(ReportError::TooManyFindings { max: TWO })));
    Ok(())
}


#[test]
fn huge_byte_limit_is_a_typed_error() -> TestResult {
    let limits = Limits {
        max_bytes: usize::MAX,
        ..Limits::default()
    };
    let result = parse_report(b"[]".as_slice(), &limits, "acme", "s", &ScanScope::default());
    assert!(matches!(result, Err(ReportError::InvalidLimits { max_bytes: usize::MAX })));
    let message = result.err().map(|error| error.to_string()).ok_or("no error")?;
    assert!(message.contains("ceiling"));
    Ok(())
}


#[test]
fn bad_field_after_the_secret_is_malformed() -> TestResult {
    let report = parse_report(
        br#"[{"File":"a","Secret":"topsecretvalue","Match":"m","StartLine":"x","EndLine":1,"RuleID":"r"}]"#.as_slice(),
        &Limits::default(),
        "acme",
        "s",
        &ScanScope::default(),
    )?;
    assert_eq!((report.malformed, report.findings.len()), (1, 0));
    Ok(())
}
