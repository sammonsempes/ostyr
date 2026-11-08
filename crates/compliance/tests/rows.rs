#[path = "common/types.rs"]
mod types;


use compliance::error::ComplianceError;
use compliance::rows::{rows_from_json, MAX_RESULT_BYTES, MAX_RESULT_ROWS};
use types::TestResult;


const EXTRA: usize = 1;


const ROW_COUNT: usize = 2;


#[test]
fn osquery_rows_are_parsed() -> TestResult {
    let rows = rows_from_json("[{\"a\":\"1\"},{\"a\":\"2\",\"b\":\"x\"}]")?;
    assert_eq!(rows.len(), ROW_COUNT);
    assert_eq!(rows.first().and_then(|row| row.get("a")), Some(&"1".to_string()));
    Ok(())
}


#[test]
fn unreadable_results_are_errors() -> TestResult {
    assert!(matches!(rows_from_json("not json"), Err(ComplianceError::UnreadableResult(_))));
    assert!(matches!(rows_from_json("[{\"a\":1}]"), Err(ComplianceError::UnreadableResult(_))));
    assert!(matches!(rows_from_json("{}"), Err(ComplianceError::UnreadableResult(_))));
    Ok(())
}


#[test]
fn oversized_results_are_refused() -> TestResult {
    let big = " ".repeat(MAX_RESULT_BYTES + EXTRA);
    assert!(matches!(rows_from_json(&big), Err(ComplianceError::ResultTooLarge { .. })));
    let many = format!("[{}]", vec!["{}"; MAX_RESULT_ROWS + EXTRA].join(","));
    assert!(matches!(rows_from_json(&many), Err(ComplianceError::TooManyRows { .. })));
    Ok(())
}
