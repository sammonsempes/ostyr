mod common;


use common::types::TestResult;
use traces_ingest::sampling::{keep_span, parse_sampling, ratio_for, Sampling, SamplingError, MAX_SAMPLING_SERVICES};


const FILE: &str = "sampling.yaml";


const SERVICES_OVER: usize = 257;


const ID_LEN: usize = 16;


const ZERO_F: f64 = 0.0;


const ONE_F: f64 = 1.0;


const HALF: f64 = 0.5;


const QUARTER: f64 = 0.25;


const THREE_QUARTERS: f64 = 0.75;


const HALF_HASH: u64 = 1 << 63;


fn parse(text: &str) -> Result<Sampling, SamplingError> {
    parse_sampling(text, FILE)
}


fn trace_with_hash(hash: u64) -> [u8; ID_LEN] {
    let mut id = [u8::MIN; ID_LEN];
    id.iter_mut().zip(hash.to_be_bytes()).for_each(|(slot, byte)| *slot = byte);
    id
}


fn services(count: usize) -> String {
    (0..count).map(|index| format!("  s{index}: 0.5\n")).collect()
}


#[test]
fn an_empty_file_keeps_everything() -> TestResult {
    let sampling = parse("{}")?;
    assert_eq!(sampling, Sampling::default());
    assert!(keep_span(&sampling, "any", &trace_with_hash(u64::MAX), false));
    Ok(())
}


#[test]
fn a_full_file_is_parsed() -> TestResult {
    let sampling = parse("default_ratio: 0.25\nerror_ratio: 1\nservices:\n  api: 0.5\n  batch: 0\n")?;
    assert_eq!(sampling.default_ratio, QUARTER);
    assert_eq!(sampling.error_ratio, Some(ONE_F));
    assert_eq!(sampling.services.get("api"), Some(&HALF));
    assert_eq!(sampling.services.get("batch"), Some(&ZERO_F));
    Ok(())
}


#[test]
fn ratios_outside_zero_to_one_are_refused() -> TestResult {
    let refused = [
        ("default_ratio: 1.5\n", "default_ratio"),
        ("default_ratio: -0.1\n", "default_ratio"),
        ("default_ratio: .nan\n", "default_ratio"),
        ("services:\n  api: 1.5\n", "services"),
        ("error_ratio: 1.5\n", "error_ratio"),
    ];
    refused.iter().try_for_each(|(text, field)| -> TestResult {
        assert!(matches!(parse(text), Err(SamplingError::Ratio { field: named }) if named == *field));
        Ok(())
    })
}


#[test]
fn error_ratio_below_a_ratio_it_overrides_is_refused() -> TestResult {
    assert!(matches!(
        parse("default_ratio: 0.5\nerror_ratio: 0.25\n"),
        Err(SamplingError::ErrorRatioBelowRatio)
    ));
    assert!(matches!(
        parse("default_ratio: 0.1\nerror_ratio: 0.5\nservices:\n  api: 0.75\n"),
        Err(SamplingError::ErrorRatioBelowRatio)
    ));
    assert!(parse("default_ratio: 0.5\nerror_ratio: 0.5\nservices:\n  api: 0.25\n").is_ok());
    Ok(())
}


#[test]
fn services_are_capped_at_n_and_n_plus_one() -> TestResult {
    assert_eq!(
        parse(&format!("services:\n{}", services(MAX_SAMPLING_SERVICES)))?.services.len(),
        MAX_SAMPLING_SERVICES
    );
    assert!(matches!(
        parse(&format!("services:\n{}", services(SERVICES_OVER))),
        Err(SamplingError::TooManyServices)
    ));
    Ok(())
}


#[test]
fn unknown_keys_and_bad_yaml_are_refused() -> TestResult {
    assert!(matches!(parse("default_ratio: 1\nextra: 1\n"), Err(SamplingError::Parse(_))));
    assert!(matches!(parse("default_ratio: [\n"), Err(SamplingError::Parse(_))));
    Ok(())
}


#[test]
fn errors_have_fixed_text() -> TestResult {
    assert_eq!(
        parse("error_ratio: 2\n").err().map(|error| error.to_string()).as_deref(),
        Some("the sampling ratio error_ratio is outside 0 to 1")
    );
    assert_eq!(
        parse(&format!("services:\n{}", services(SERVICES_OVER)))
            .err()
            .map(|error| error.to_string())
            .as_deref(),
        Some("the sampling file names more than 256 services")
    );
    Ok(())
}


#[test]
fn the_threshold_is_hash_below_ratio_times_two_pow_64() -> TestResult {
    let half = Sampling {
        default_ratio: HALF,
        ..Sampling::default()
    };
    assert!(keep_span(&half, "x", &trace_with_hash(HALF_HASH - 1), false));
    assert!(!keep_span(&half, "x", &trace_with_hash(HALF_HASH), false));
    let zero = Sampling {
        default_ratio: ZERO_F,
        ..Sampling::default()
    };
    assert!(!keep_span(&zero, "x", &trace_with_hash(0), false));
    let one = Sampling::default();
    assert!(keep_span(&one, "x", &trace_with_hash(u64::MAX), false));
    Ok(())
}


#[test]
fn ratio_selection_is_error_then_service_then_default() -> TestResult {
    let mut sampling = Sampling {
        default_ratio: QUARTER,
        error_ratio: Some(THREE_QUARTERS),
        ..Sampling::default()
    };
    sampling.services.insert("api".to_string(), HALF);
    assert_eq!(ratio_for(&sampling, "api", true), THREE_QUARTERS);
    assert_eq!(ratio_for(&sampling, "api", false), HALF);
    assert_eq!(ratio_for(&sampling, "other", false), QUARTER);
    assert_eq!(ratio_for(&sampling, "other", true), THREE_QUARTERS);
    sampling.error_ratio = None;
    assert_eq!(ratio_for(&sampling, "other", true), QUARTER);
    Ok(())
}
