#[path = "common/types.rs"]
mod types;


use std::io::{BufReader, Error, Read};
use types::TestResult;
use vuln_match::epss::{parse_epss, EpssLimits};
use vuln_match::error::EpssError;
use vuln_match::kev::KevCatalogue;
use vuln_match::model::{Criticality, Finding, ScoredFinding};
use vuln_match::scoring::score_findings;


const SAMPLE: &[u8] = include_bytes!("fixtures/epss_sample.csv");


const SAMPLE_ROWS: usize = 200;


const LONG_LINE: usize = 10_000_000;


const COLUMNS: usize = 10_000;


const HEAD: &str = "#model_version:v1,score_date:2026-01-01T00:00:00Z\ncve,epss,percentile\n";


const SMALL_LINE: usize = 64;


const TWO: usize = 2;


const SMALL_TEXT: usize = 2;


const HALF: f64 = 0.5;


const ZERO: f64 = 0.0;


const ONE: f64 = 1.0;


const FIRST_SCORE: f64 = 0.04753;


const LONG_LINE_NUMBER: usize = 4;


const NINE_TENTHS: f64 = 0.9;


const QUARTER: f64 = 0.25;


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(Error::other("injected"))
    }
}


fn parse(text: &str) -> Result<vuln_match::epss::EpssScores, EpssError> {
    parse_epss(text.as_bytes(), &EpssLimits::default())
}


#[test]
fn golden_sample() -> TestResult {
    let parsed = parse_epss(SAMPLE, &EpssLimits::default())?;
    assert_eq!(parsed.scores.len(), SAMPLE_ROWS);
    assert_eq!((parsed.bad_rows, parsed.duplicates), (0, 0));
    assert_eq!(parsed.model_version, "v2026.06.15");
    assert_eq!(parsed.score_date, "2026-11-11T12:00:22Z");
    assert_eq!(parsed.scores.get("CVE-1999-0001"), Some(&FIRST_SCORE));
    Ok(())
}


#[test]
fn bad_rows_are_counted_never_kept() -> TestResult {
    let rows = [
        "CVE-2024-0001,NaN,0.5",
        "CVE-2024-0002,inf,0.5",
        "CVE-2024-0003,1.5,0.5",
        "CVE-2024-0004,-0.1,0.5",
        "CVE-2024-0005,,0.5",
        "CVE-2024-0006,0.5,2",
        "CVE-2024-0007,0.5",
        "CVE-2024-0008,0.5,0.5,0.5",
        "cve-2024-0009,0.5,0.5",
        "CVE-24-1,0.5,0.5",
        "",
        "CVE-2024-0010,0.5,0.5\u{fffd}",
        "CVE-2024-0011,0.9,0.1",
    ];
    let parsed = parse(&format!("{HEAD}{}\n", rows.join("\n")))?;
    assert_eq!(parsed.bad_rows, rows.len() - 1);
    assert_eq!(parsed.scores.len(), 1);
    assert_eq!(parsed.scores.get("CVE-2024-0011"), Some(&NINE_TENTHS));
    Ok(())
}


#[test]
fn bounds_of_the_unit_interval_are_accepted() -> TestResult {
    let parsed = parse(&format!("{HEAD}CVE-2024-0001,0,1\r\nCVE-2024-0002,1,0"))?;
    assert_eq!(parsed.bad_rows, 0);
    assert_eq!(parsed.scores.get("CVE-2024-0001"), Some(&ZERO));
    assert_eq!(parsed.scores.get("CVE-2024-0002"), Some(&ONE));
    Ok(())
}


#[test]
fn duplicates_first_wins() -> TestResult {
    let parsed = parse(&format!("{HEAD}CVE-2024-0001,0.5,0.5\nCVE-2024-0001,0.25,0.5\n"))?;
    assert_eq!(parsed.duplicates, 1);
    assert_eq!(parsed.scores.get("CVE-2024-0001"), Some(&HALF));
    Ok(())
}


#[test]
fn header_and_meta_errors() -> TestResult {
    assert!(matches!(
        parse("#model_version:v1,score_date:d\ncve,percentile,epss\n"),
        Err(EpssError::BadHeader)
    ));
    assert!(matches!(parse("#model_version:v1,score_date:d\n"), Err(EpssError::BadHeader)));
    assert!(matches!(
        parse("model_version:v1,score_date:d\ncve,epss,percentile\n"),
        Err(EpssError::BadMeta)
    ));
    assert!(matches!(parse("#model_version:v1\ncve,epss,percentile\n"), Err(EpssError::BadMeta)));
    assert!(matches!(parse(""), Err(EpssError::BadMeta)));
    Ok(())
}


#[test]
fn meta_text_is_bounded() -> TestResult {
    let limits = EpssLimits {
        max_text_chars: SMALL_TEXT,
        ..EpssLimits::default()
    };
    let parsed = parse_epss(HEAD.as_bytes(), &limits)?;
    assert_eq!(parsed.model_version, "v1");
    assert_eq!(parsed.score_date, "20[cut]");
    Ok(())
}


#[test]
fn row_cap_is_exact() -> TestResult {
    let body = format!("{HEAD}CVE-2024-0001,0.5,0.5\nbad\n");
    let exact = EpssLimits {
        max_rows: TWO,
        ..EpssLimits::default()
    };
    assert_eq!(parse_epss(body.as_bytes(), &exact)?.bad_rows, 1);
    let below = EpssLimits {
        max_rows: 1,
        ..EpssLimits::default()
    };
    assert!(matches!(parse_epss(body.as_bytes(), &below), Err(EpssError::TooMany { max: 1 })));
    Ok(())
}


#[test]
fn byte_cap_is_exact() -> TestResult {
    let exact = EpssLimits {
        max_bytes: HEAD.len() as u64,
        ..EpssLimits::default()
    };
    assert!(parse_epss(HEAD.as_bytes(), &exact).is_ok());
    let below = EpssLimits {
        max_bytes: HEAD.len() as u64 - 1,
        ..EpssLimits::default()
    };
    assert!(matches!(parse_epss(HEAD.as_bytes(), &below), Err(EpssError::TooLarge { .. })));
    Ok(())
}


#[test]
fn long_lines_are_refused_not_buffered() -> TestResult {
    let limits = EpssLimits {
        max_line_bytes: SMALL_LINE,
        ..EpssLimits::default()
    };
    let long = format!("{HEAD}CVE-2024-0001,0.5,0.5\n{}\n", "a".repeat(LONG_LINE));
    assert!(matches!(
        parse_epss(long.as_bytes(), &limits),
        Err(EpssError::LineTooLong {
            line: LONG_LINE_NUMBER,
            max: SMALL_LINE
        })
    ));
    let wide = format!("{HEAD}{}\n", vec!["0"; COLUMNS].join(","));
    assert!(matches!(parse_epss(wide.as_bytes(), &limits), Err(EpssError::LineTooLong { .. })));
    Ok(())
}


#[test]
fn read_error_is_typed() -> TestResult {
    assert!(matches!(
        parse_epss(BufReader::new(Failing), &EpssLimits::default()),
        Err(EpssError::Io(_))
    ));
    Ok(())
}


fn finding(record: &str, aliases: &[&str]) -> ScoredFinding {
    ScoredFinding {
        finding: Finding {
            package: "pkg".into(),
            installed_version: "1".into(),
            ecosystem: "Debian".into(),
            record_id: record.into(),
            cve_aliases: aliases.iter().map(|alias| alias.to_string()).collect(),
            fixed_version: None,
        },
        cvss: ZERO,
        epss: ZERO,
        kev: false,
        criticality: Criticality::Low,
    }
}


#[test]
fn score_findings_by_id_and_alias() -> TestResult {
    let epss = parse(&format!("{HEAD}CVE-2024-0001,0.5,0.5\nCVE-2024-0002,0.25,0.5\n"))?;
    let mut kev = KevCatalogue::default();
    kev.ids.insert("CVE-2024-0002".into());
    let findings = [
        finding("DSA-1", &["CVE-2024-0001", "CVE-2024-0002"]),
        finding("CVE-2024-0002", &[]),
        finding("DSA-2", &["CVE-2024-9999"]),
    ];
    let scored = score_findings(&findings, &epss, &kev);
    let first = scored.first().ok_or("missing")?;
    assert_eq!((first.epss, first.kev), (HALF, true));
    let second = scored.get(1).ok_or("missing")?;
    assert_eq!((second.epss, second.kev), (QUARTER, true));
    assert_eq!(scored.get(TWO), findings.get(TWO));
    let flagged = ScoredFinding {
        kev: true,
        epss: HALF,
        ..finding("DSA-3", &[])
    };
    assert_eq!(
        score_findings(std::slice::from_ref(&flagged), &epss, &KevCatalogue::default()),
        vec![flagged]
    );
    Ok(())
}
