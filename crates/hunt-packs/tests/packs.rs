mod common;


use common::types::TestResult;
use hunt_packs::error::{shown_id, PackError};
use hunt_packs::model::{Baseline, Cost, HuntPack, PackTest, Source};
use hunt_packs::packs::{
    is_pack_id, is_technique, parse_packs, validate_pack, validate_pack_file, MAX_BYTES_READ_CEILING, MAX_CORPUS_BYTES, MAX_FILE_BYTES,
    MAX_HYPOTHESIS_BYTES, MAX_PACKS, MAX_QUERY_BYTES, MAX_ROWS_CEILING, MAX_SCHEDULE_SECONDS, MAX_SECONDS_CEILING, MAX_TESTS, MAX_TITLE_BYTES,
    MAX_WINDOW_SECONDS, MIN_SCHEDULE_SECONDS, MIN_WINDOW_SECONDS,
};
use hunt_packs::text::{is_hidden, valid_text};
use std::error::Error;
use std::io::{self, Read};


pub struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected failure"))
    }
}


const FILE: &str = "packs.yaml";


const QUERY_MARKER: &str = "SECRETMARKER";


const SCHEDULE: u64 = 3_600;


const WINDOW: u64 = 86_400;


const LONG_ID: usize = 65;


const ROWS: u64 = 1_000;


const SECONDS: u64 = 10;


const BYTES: u64 = 1_000_000;


pub fn pack() -> HuntPack {
    HuntPack {
        id: "rare-parent".to_string(),
        title: "Rare parent".to_string(),
        hypothesis: "A shell starts from an office process".to_string(),
        technique: "T1059.001".to_string(),
        source: Source::Clickhouse,
        query: format!("SELECT '{QUERY_MARKER}' FROM events;"),
        schedule_seconds: SCHEDULE,
        window_seconds: WINDOW,
        cost: Cost {
            max_rows: ROWS,
            max_seconds: SECONDS,
            max_bytes_read: Some(BYTES),
        },
        baseline: Baseline { max_matches: 0 },
        tests: vec![PackTest {
            corpus: "corpus/rare.ndjson".to_string(),
            expect_matches: 1,
        }],
    }
}


pub fn field_refused(change: impl FnOnce(&mut HuntPack)) -> Result<String, Box<dyn Error>> {
    let mut candidate = pack();
    change(&mut candidate);
    let error = validate_pack(FILE, &candidate).err().ok_or("pack accepted")?;
    let text = error.to_string();
    assert!(!text.contains(QUERY_MARKER), "{text}");
    Ok(match error {
        PackError::Invalid { field, .. } => field.to_string(),
        other => other.to_string(),
    })
}


#[test]
fn valid_pack_passes() -> TestResult {
    validate_pack(FILE, &pack())?;
    let mut osquery = pack();
    osquery.source = Source::Osquery;
    osquery.cost.max_bytes_read = None;
    osquery.window_seconds = MIN_WINDOW_SECONDS;
    validate_pack(FILE, &osquery)?;
    Ok(())
}


#[test]
fn id_grammar() -> TestResult {
    assert!(is_pack_id("a"));
    assert!(is_pack_id("0-a_b.c"));
    assert!(is_pack_id("a1"));
    assert!(!is_pack_id(""));
    assert!(!is_pack_id("-a"));
    assert!(!is_pack_id("A"));
    assert!(!is_pack_id("a b"));
    assert!(!is_pack_id(&"a".repeat(LONG_ID)));
    assert_eq!(field_refused(|candidate| candidate.id = "-x".to_string())?, "id");
    Ok(())
}


#[test]
fn technique_grammar() -> TestResult {
    assert!(is_technique("T1059"));
    assert!(is_technique("T1059.001"));
    ["T12345", "T105", "1059", "T1059.01", "T1059.0011", "T1059.", "Tabcd", "t1059", ""]
        .iter()
        .for_each(|text| assert!(!is_technique(text), "{text}"));
    assert_eq!(field_refused(|candidate| candidate.technique = "T12345".to_string())?, "technique");
    Ok(())
}


#[test]
fn text_fields() -> TestResult {
    assert_eq!(field_refused(|candidate| candidate.title = String::new())?, "title");
    assert_eq!(field_refused(|candidate| candidate.title = "a".repeat(MAX_TITLE_BYTES + 1))?, "title");
    assert_eq!(field_refused(|candidate| candidate.title = "-lead".to_string())?, "title");
    assert_eq!(field_refused(|candidate| candidate.title = "a\u{202e}b".to_string())?, "title");
    assert_eq!(field_refused(|candidate| candidate.hypothesis = "two\nlines".to_string())?, "hypothesis");
    assert_eq!(
        field_refused(|candidate| candidate.hypothesis = "a".repeat(MAX_HYPOTHESIS_BYTES + 1))?,
        "hypothesis"
    );
    assert!(is_hidden('\u{200b}'));
    assert!(!is_hidden('a'));
    assert!(valid_text("plain", MAX_TITLE_BYTES));
    Ok(())
}


#[test]
fn query_checks() -> TestResult {
    assert_eq!(field_refused(|candidate| candidate.query = String::new())?, "query");
    assert_eq!(field_refused(|candidate| candidate.query = " ;".to_string())?, "query");
    assert_eq!(field_refused(|candidate| candidate.query = "SELECT 1; SELECT 2".to_string())?, "query");
    assert_eq!(field_refused(|candidate| candidate.query = "SELECT 1;;".to_string())?, "query");
    assert_eq!(field_refused(|candidate| candidate.query = "SELECT 1\0".to_string())?, "query");
    assert_eq!(field_refused(|candidate| candidate.query = "a".repeat(MAX_QUERY_BYTES + 1))?, "query");
    let mut trailing = pack();
    trailing.query = "SELECT 1\n;\n".to_string();
    validate_pack(FILE, &trailing)?;
    trailing.query = "SELECT 1".to_string();
    validate_pack(FILE, &trailing)?;
    Ok(())
}


#[test]
fn schedule_and_window() -> TestResult {
    assert_eq!(
        field_refused(|candidate| candidate.schedule_seconds = MIN_SCHEDULE_SECONDS - 1)?,
        "schedule_seconds"
    );
    assert_eq!(
        field_refused(|candidate| candidate.schedule_seconds = MAX_SCHEDULE_SECONDS + 1)?,
        "schedule_seconds"
    );
    assert_eq!(
        field_refused(|candidate| candidate.window_seconds = MIN_WINDOW_SECONDS - 1)?,
        "window_seconds"
    );
    assert_eq!(
        field_refused(|candidate| candidate.window_seconds = MAX_WINDOW_SECONDS + 1)?,
        "window_seconds"
    );
    assert_eq!(field_refused(|candidate| candidate.window_seconds = SCHEDULE - 1)?, "window_seconds");
    Ok(())
}


#[test]
fn cost_checks() -> TestResult {
    assert_eq!(field_refused(|candidate| candidate.cost.max_rows = 0)?, "cost.max_rows");
    assert_eq!(
        field_refused(|candidate| candidate.cost.max_rows = MAX_ROWS_CEILING + 1)?,
        "cost.max_rows"
    );
    assert_eq!(field_refused(|candidate| candidate.cost.max_seconds = 0)?, "cost.max_seconds");
    assert_eq!(
        field_refused(|candidate| candidate.cost.max_seconds = MAX_SECONDS_CEILING + 1)?,
        "cost.max_seconds"
    );
    assert_eq!(field_refused(|candidate| candidate.cost.max_bytes_read = None)?, "cost.max_bytes_read");
    assert_eq!(field_refused(|candidate| candidate.cost.max_bytes_read = Some(0))?, "cost.max_bytes_read");
    assert_eq!(
        field_refused(|candidate| candidate.cost.max_bytes_read = Some(MAX_BYTES_READ_CEILING + 1))?,
        "cost.max_bytes_read"
    );
    assert_eq!(
        field_refused(|candidate| {
            candidate.source = Source::Osquery;
        })?,
        "cost.max_bytes_read"
    );
    assert_eq!(
        field_refused(|candidate| candidate.baseline.max_matches = MAX_ROWS_CEILING + 1)?,
        "baseline.max_matches"
    );
    Ok(())
}


pub fn corpus_pack(path: String) -> impl FnOnce(&mut HuntPack) {
    move |candidate| {
        candidate.tests = vec![PackTest {
            corpus: path,
            expect_matches: 1,
        }]
    }
}


#[test]
fn test_cases() -> TestResult {
    ["/etc/passwd", "../x", "a/../x", "a//b", "./a", "-a", "a\\b", "", "a\nb"]
        .iter()
        .try_for_each(|text| field_refused(corpus_pack(text.to_string())).map(|field| assert_eq!(field, "tests", "{text}")))?;
    assert_eq!(field_refused(corpus_pack("a".repeat(MAX_CORPUS_BYTES + 1)))?, "tests");
    assert_eq!(
        field_refused(|candidate| candidate.tests = (0..=MAX_TESTS).map(|_| corpus_case()).collect())?,
        "tests"
    );
    assert_eq!(
        field_refused(|candidate| candidate.tests = vec![PackTest {
            corpus: "a".to_string(),
            expect_matches: MAX_ROWS_CEILING + 1,
        }])?,
        "tests"
    );
    Ok(())
}


pub fn corpus_case() -> PackTest {
    PackTest {
        corpus: "a".to_string(),
        expect_matches: 1,
    }
}


#[test]
fn file_level_checks() -> TestResult {
    let duplicated = hunt_packs::model::HuntPackFile { packs: vec![pack(), pack()] };
    let error = validate_pack_file(&duplicated, FILE).err().ok_or("accepted")?;
    assert!(matches!(error, PackError::DuplicateId { .. }));
    assert!(error.to_string().contains("duplicate pack id `rare-parent`"));
    let many = hunt_packs::model::HuntPackFile {
        packs: (0..=MAX_PACKS).map(|_| pack()).collect(),
    };
    let many_error = validate_pack_file(&many, FILE).err().ok_or("accepted")?;
    assert!(matches!(many_error, PackError::TooManyPacks { count, .. } if count == MAX_PACKS + 1));
    assert!(many_error.to_string().contains("at most"));
    Ok(())
}


const VALID_YAML: &str = "packs:
  - id: a
    title: T
    hypothesis: H
    technique: T1059
    source: osquery
    query: SELECT 1
    schedule_seconds: 300
    window_seconds: 60
    cost: { max_rows: 1, max_seconds: 1 }
    baseline: { max_matches: 0 }
";


#[test]
fn parse_valid_and_defaults() -> TestResult {
    let parsed = parse_packs(&mut VALID_YAML.as_bytes(), FILE)?;
    assert_eq!(parsed.packs.len(), 1);
    assert!(parsed.packs.first().ok_or("no pack")?.tests.is_empty());
    Ok(())
}


#[test]
fn parse_refusals() -> TestResult {
    let unknown = format!("{VALID_YAML}    extra: 1\n");
    let error = parse_packs(&mut unknown.as_bytes(), FILE).err().ok_or("accepted")?;
    assert!(matches!(error, PackError::Config(_)));
    let bad_source = VALID_YAML.replace("osquery", "splunk");
    assert!(parse_packs(&mut bad_source.as_bytes(), FILE).is_err());
    let invalid = VALID_YAML.replace("T1059", "T12345");
    let invalid_error = parse_packs(&mut invalid.as_bytes(), FILE).err().ok_or("accepted")?;
    assert_eq!(invalid_error.to_string(), "packs.yaml: pack `a`: invalid `technique`");
    let reader_error = parse_packs(&mut FailingReader, FILE).err().ok_or("accepted")?;
    assert!(matches!(reader_error, PackError::Config(_)));
    let big = format!("{VALID_YAML}#{}", "a".repeat(usize::try_from(MAX_FILE_BYTES)?));
    assert!(matches!(parse_packs(&mut big.as_bytes(), FILE), Err(PackError::FileTooLarge { .. })));
    Ok(())
}


#[test]
fn shown_ids() -> TestResult {
    assert_eq!(shown_id("a-b.c_d"), "a-b.c_d");
    let hidden = shown_id("a\u{202e}b");
    assert!(hidden.starts_with('#'));
    assert!(!hidden.contains('\u{202e}'));
    assert!(shown_id(&"a".repeat(LONG_ID)).starts_with('#'));
    Ok(())
}
