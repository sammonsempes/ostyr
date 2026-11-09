#[path = "common/types.rs"]
mod types;


use sbom::error::SbomError;
use sbom::model::{Limits, Sbom};
use sbom::parse::parse_cyclonedx;
use std::error::Error;
use std::io::Cursor;
use types::TestResult;


const FIXTURE: &str = include_str!("fixtures/syft-debian.cdx.json");


const HUGE: usize = 1_000_000;


const CHAIN_BOUND: usize = 2048;


const SMALL_STRING: usize = 8;


const MAX_TINY_BYTES: usize = 6;


fn parse(text: &str, limits: &Limits) -> Result<Sbom, SbomError> {
    parse_cyclonedx(Cursor::new(text.as_bytes().to_vec()), "tenant-a", "web:1.0", limits)
}


fn parse_default(text: &str) -> Result<Sbom, SbomError> {
    parse(text, &Limits::default())
}


fn chain_text(error: &SbomError) -> String {
    let causes: Vec<String> = std::iter::successors(Some(error as &dyn Error), |cause: &&dyn Error| (*cause).source())
        .map(|cause| format!("{cause} {cause:?}"))
        .collect();
    causes.join(" ")
}


#[test]
fn huge_key_in_a_skipped_value_keeps_the_error_chain_small() -> TestResult {
    let text = format!(r#"{{"x":{{"{}":1,}}}}"#, "k".repeat(HUGE));
    let error = parse_default(&text).err().ok_or("no error")?;
    assert!(chain_text(&error).len() < CHAIN_BOUND);
    Ok(())
}


#[test]
fn huge_key_is_refused_before_it_is_buffered() -> TestResult {
    let text = format!(r#"{{"{}":1}}"#, "k".repeat(HUGE));
    let error = parse_default(&text).err().ok_or("no error")?;
    assert!(matches!(error, SbomError::NameTooLong { .. }));
    assert!(chain_text(&error).len() < CHAIN_BOUND);
    let inner = format!(r#"{{"components":[{{"{}":1}}]}}"#, "k".repeat(HUGE));
    assert!(matches!(parse_default(&inner).err().ok_or("no error")?, SbomError::NameTooLong { .. }));
    Ok(())
}


#[test]
fn name_at_the_cap_is_read() -> TestResult {
    let limits = Limits {
        max_string_bytes: SMALL_STRING,
        ..Limits::default()
    };
    let text = format!(r#"{{"{}":1,"components":[{{"name":"a"}}]}}"#, "k".repeat(SMALL_STRING));
    assert_eq!(parse(&text, &limits)?.components.len(), 1);
    Ok(())
}


#[test]
fn huge_value_is_skipped_not_buffered() -> TestResult {
    let text = format!(r#"{{"components":[{{"name":"{}"}},{{"name":"ok"}}]}}"#, "v".repeat(HUGE));
    let sbom = parse_default(&text)?;
    assert_eq!((sbom.components.len(), sbom.skipped), (1, 1));
    Ok(())
}


#[test]
fn string_with_a_bad_escape_is_an_error_with_its_cause() -> TestResult {
    let error = parse_default(r#"{"components":[{"name":"a\q"}]}"#).err().ok_or("no error")?;
    assert!(matches!(error, SbomError::Read(_)));
    assert!(error.source().is_some());
    Ok(())
}


#[test]
fn tiny_byte_limits_never_panic() -> TestResult {
    let documents = [FIXTURE, r#"{"components":[{"name":"a"}]}"#, "{", "{}", r#"{"components":["#, ""];
    (0..=MAX_TINY_BYTES).for_each(|max_bytes| {
        let limits = Limits {
            max_bytes,
            ..Limits::default()
        };
        documents.iter().for_each(|text| {
            let outcome = parse(text, &limits);
            assert!(outcome.is_err() || text.len() <= max_bytes);
        });
    });
    Ok(())
}
