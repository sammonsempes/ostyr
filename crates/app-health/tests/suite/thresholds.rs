use crate::suite::common::{TestResult, THRESHOLDS};
use app_health::error::NtpError;
use app_health::thresholds::load_thresholds;


const FILE: &str = include_str!("../fixtures/thresholds.yaml");


fn document(offset: &str, stratum: &str) -> String {
    format!("max_offset_seconds: {offset}\nmax_stratum: {stratum}\nrequire_synchronized: true\n")
}


#[test]
fn loads_the_fixture() -> TestResult {
    let loaded = load_thresholds(FILE, "thresholds.yaml")?;
    assert_eq!(loaded, THRESHOLDS);
    Ok(())
}


#[test]
fn boundaries_are_inclusive_where_stated() -> TestResult {
    load_thresholds(&document("3600", "15"), "t")?;
    load_thresholds(&document("0.001", "1"), "t")?;
    Ok(())
}


#[test]
fn out_of_range_values_are_refused() -> TestResult {
    let cases = [
        ("0", "5", "max_offset_seconds"),
        ("-1", "5", "max_offset_seconds"),
        ("3600.5", "5", "max_offset_seconds"),
        (".nan", "5", "max_offset_seconds"),
        ("1", "0", "max_stratum"),
        ("1", "16", "max_stratum"),
    ];
    cases.iter().for_each(|(offset, stratum, field)| {
        let result = load_thresholds(&document(offset, stratum), "t");
        assert!(
            matches!(result, Err(NtpError::OutOfRange { field: found }) if found == *field),
            "{offset} {stratum}"
        );
    });
    Ok(())
}


#[test]
fn unknown_and_missing_fields_are_refused() -> TestResult {
    let extra = format!("{}extra: 1\n", document("1", "5"));
    assert!(matches!(load_thresholds(&extra, "t"), Err(NtpError::Config(_))));
    assert!(matches!(load_thresholds("max_stratum: 5\n", "t"), Err(NtpError::Config(_))));
    Ok(())
}
