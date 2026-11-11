#[path = "common/types.rs"]
mod types;


use oncall::error::HolderError;
use oncall::holder::{process_holder, validate_holder};
use oncall::limits::MAX_HOLDER_CHARS;
use types::TestResult;


const PID: u32 = 4242;


fn zeros(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    buffer.fill(0);
    Ok(())
}


fn ones(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    buffer.fill(1);
    Ok(())
}


fn broken(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


#[test]
fn an_empty_long_or_non_token_id_is_refused() -> TestResult {
    assert!(matches!(validate_holder(""), Err(HolderError::Invalid)));
    assert!(matches!(validate_holder("poller b"), Err(HolderError::Invalid)));
    assert!(matches!(validate_holder("poller\n"), Err(HolderError::Invalid)));
    assert!(matches!(validate_holder(&"a".repeat(MAX_HOLDER_CHARS + 1)), Err(HolderError::Invalid)));
    assert!(validate_holder("poller-b.1_x").is_ok());
    assert!(validate_holder(&"a".repeat(MAX_HOLDER_CHARS)).is_ok());
    Ok(())
}


#[test]
fn two_processes_with_the_same_configured_label_get_different_ids() -> TestResult {
    let first = process_holder(Some("poller-b"), "host", PID, zeros)?;
    let second = process_holder(Some("poller-b"), "host", PID, ones)?;
    assert_ne!(first, second);
    assert!(first.starts_with("poller-b-4242-") && validate_holder(&first).is_ok());
    Ok(())
}


#[test]
fn a_configured_label_that_is_not_a_token_is_refused_at_load() -> TestResult {
    assert!(matches!(process_holder(Some(""), "host", PID, zeros), Err(HolderError::Invalid)));
    assert!(matches!(process_holder(Some("a b"), "host", PID, zeros), Err(HolderError::Invalid)));
    Ok(())
}


#[test]
fn the_default_id_comes_from_the_sanitised_host_pid_and_random_and_stays_a_valid_token() -> TestResult {
    let named = process_holder(None, "web 1/x", PID, zeros)?;
    assert!(named.starts_with("web-1-x-4242-") && validate_holder(&named).is_ok());
    let unnamed = process_holder(None, "", PID, zeros)?;
    assert!(validate_holder(&unnamed).is_ok());
    let long = process_holder(None, &"h".repeat(MAX_HOLDER_CHARS + MAX_HOLDER_CHARS), PID, ones)?;
    assert_eq!(long.chars().count(), MAX_HOLDER_CHARS);
    assert_ne!(process_holder(None, "h", PID, zeros)?, process_holder(None, "h", PID, ones)?);
    Ok(())
}


#[test]
fn a_failing_random_source_is_an_error() -> TestResult {
    assert!(matches!(process_holder(None, "h", PID, broken), Err(HolderError::Random(_))));
    Ok(())
}
