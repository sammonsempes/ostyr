#[path = "common/types.rs"]
mod types;


use grc::error::GrcError;
use grc::evidence::{canonical_text, canonical_value, digest_of, make_evidence, verify_evidence};
use grc::inputs::parse_indicators;
use types::TestResult;


const VALUE: f64 = 87.5;


const OBSERVED: i64 = 1_800_000_000;


const NEGATIVE_ZERO: f64 = -0.0;


const POSITIVE_ZERO: f64 = 0.0;


const OTHER_VALUE: f64 = 87.6;


const DIGEST_HEX_LENGTH: usize = 64;


const INTEGER_JSON: &str = r#"[{"tenant":"acme","name":"edr.share","value":1,"observed_at":"2026-11-12T10:00:00Z","source":"edr"}]"#;


const FLOAT_JSON: &str = r#"[{"tenant":"acme","name":"edr.share","value":1.0,"observed_at":"2026-11-12T10:00:00Z","source":"edr"}]"#;


#[test]
fn a_digest_is_sixty_four_lowercase_hex_digits() -> TestResult {
    let digest = digest_of("edr.share", VALUE, OBSERVED, "edr");
    assert_eq!(digest.len(), DIGEST_HEX_LENGTH);
    assert!(digest
        .chars()
        .all(|character| character.is_ascii_digit() || ('a'..='f').contains(&character)));
    Ok(())
}


#[test]
fn fresh_evidence_verifies() -> TestResult {
    verify_evidence(&make_evidence("edr.share", VALUE, OBSERVED, "edr"))?;
    Ok(())
}


#[test]
fn changing_any_field_breaks_the_digest() -> TestResult {
    let original = make_evidence("edr.share", VALUE, OBSERVED, "edr");
    let mut indicator = original.clone();
    indicator.indicator = "edr.other".to_owned();
    let mut value = original.clone();
    value.value = OTHER_VALUE;
    let mut observed = original.clone();
    observed.observed_at += 1;
    let mut source = original.clone();
    source.source = "edr2".to_owned();
    let mut digest = original;
    digest.sha256 = digest.sha256.to_uppercase();
    for tampered in [indicator, value, observed, source, digest] {
        assert!(matches!(verify_evidence(&tampered), Err(GrcError::EvidenceMismatch)));
    }
    Ok(())
}


#[test]
fn one_and_one_point_zero_have_the_same_canonical_form() -> TestResult {
    let integer = parse_indicators(&mut INTEGER_JSON.as_bytes(), "i.json")?;
    let float = parse_indicators(&mut FLOAT_JSON.as_bytes(), "f.json")?;
    let integer_value = integer.first().ok_or("no value")?.value;
    let float_value = float.first().ok_or("no value")?.value;
    assert_eq!(canonical_value(integer_value), "1");
    assert_eq!(digest_of("n", integer_value, OBSERVED, "s"), digest_of("n", float_value, OBSERVED, "s"));
    Ok(())
}


#[test]
fn negative_zero_reads_as_zero() -> TestResult {
    assert_eq!(canonical_value(NEGATIVE_ZERO), "0");
    assert_eq!(digest_of("n", NEGATIVE_ZERO, OBSERVED, "s"), digest_of("n", POSITIVE_ZERO, OBSERVED, "s"));
    Ok(())
}


#[test]
fn text_cannot_shift_between_fields() -> TestResult {
    assert_ne!(canonical_text("a", VALUE, OBSERVED, "bc"), canonical_text("ab", VALUE, OBSERVED, "c"));
    assert_ne!(digest_of("a", VALUE, OBSERVED, "bc"), digest_of("ab", VALUE, OBSERVED, "c"));
    Ok(())
}
