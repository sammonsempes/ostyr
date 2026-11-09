#[path = "support/types.rs"]
mod types;


use proptest::prelude::*;
use site_collector::error::ParseError;
use site_collector::model::{SdElement, MAX_APP_BYTES, MAX_HOST_BYTES, MAX_SD_ELEMENTS, MAX_SD_PARAMS, MAX_SD_STRING_BYTES};
use site_collector::parse::parse_syslog;
use types::TestResult;


const YEAR: i32 = 2003;


const PRIORITY_AUTH: u8 = 34;


const PRIORITY_LOCAL4: u8 = 165;


const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


const RFC_TIMESTAMP: i64 = 1_065_910_455;


const FUZZ_MAX_LEN: usize = 300;


#[test]
fn rfc5424_example_without_structured_data() -> TestResult {
    let line = "<34>1 2003-10-11T22:14:15.003Z mymachine.example.com su - ID47 - 'su root' failed for lonvick on /dev/pts/8";
    let record = parse_syslog(line.as_bytes(), YEAR)?;
    assert_eq!(record.priority, PRIORITY_AUTH);
    assert_eq!(record.timestamp, Some(RFC_TIMESTAMP));
    assert_eq!(record.host.as_deref(), Some("mymachine.example.com"));
    assert_eq!(record.app.as_deref(), Some("su"));
    assert_eq!(record.message, "'su root' failed for lonvick on /dev/pts/8");
    assert!(record.structured_data.is_empty());
    Ok(())
}


#[test]
fn rfc5424_example_with_structured_data() -> TestResult {
    let line =
        "<165>1 2003-10-11T22:14:15.003Z mymachine.example.com evntslog - ID47 [exampleSDID@32473 iut=\"3\" eventSource=\"Application\"] An event";
    let record = parse_syslog(line.as_bytes(), YEAR)?;
    assert_eq!(record.priority, PRIORITY_LOCAL4);
    assert_eq!(
        record.structured_data,
        vec![SdElement {
            id: "exampleSDID@32473".to_string(),
            params: vec![
                ("iut".to_string(), "3".to_string()),
                ("eventSource".to_string(), "Application".to_string())
            ],
        }]
    );
    Ok(())
}


#[test]
fn rfc3164_example() -> TestResult {
    let line = "<34>Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8";
    let record = parse_syslog(line.as_bytes(), YEAR)?;
    assert_eq!(record.priority, PRIORITY_AUTH);
    assert_eq!(record.timestamp, Some(RFC_TIMESTAMP));
    assert_eq!(record.host.as_deref(), Some("mymachine"));
    assert_eq!(record.app.as_deref(), Some("su"));
    assert_eq!(record.message, "'su root' failed for lonvick on /dev/pts/8");
    Ok(())
}


#[test]
fn invalid_utf8_is_an_error() -> TestResult {
    let result = parse_syslog(&INVALID_UTF8, YEAR);
    assert!(matches!(result, Err(ParseError::NotUtf8(_))));
    Ok(())
}


#[test]
fn garbage_is_an_error() -> TestResult {
    let result = parse_syslog(b"", YEAR);
    assert!(result.is_err());
    let result_text = parse_syslog(b"just some text", YEAR);
    assert!(result_text.is_err());
    Ok(())
}


#[test]
fn oversized_host_and_app_are_refused() -> TestResult {
    let host = "h".repeat(MAX_HOST_BYTES + 1);
    let line = format!("<34>1 2003-10-11T22:14:15Z {host} su - - - x");
    assert_eq!(parse_syslog(line.as_bytes(), YEAR), Err(ParseError::FieldTooLong("hostname")));
    let app = "a".repeat(MAX_APP_BYTES + 1);
    let app_line = format!("<34>1 2003-10-11T22:14:15Z host {app} - - - x");
    assert_eq!(parse_syslog(app_line.as_bytes(), YEAR), Err(ParseError::FieldTooLong("app")));
    Ok(())
}


#[test]
fn structured_data_bounds_are_enforced() -> TestResult {
    let prefix = "<34>1 2003-10-11T22:14:15Z host app - - ";
    let elements = "[a b=\"c\"]".repeat(MAX_SD_ELEMENTS + 1);
    let too_many_elements = format!("{prefix}{elements} x");
    let params = " p=\"v\"".repeat(MAX_SD_PARAMS + 1);
    let too_many_params = format!("{prefix}[a{params}] x");
    let long = "v".repeat(MAX_SD_STRING_BYTES + 1);
    let long_value = format!("{prefix}[a p=\"{long}\"] x");
    let long_name = format!("{prefix}[a {long}=\"v\"] x");
    let long_id = format!("{prefix}[{long} p=\"v\"] x");
    [too_many_elements, too_many_params, long_value, long_name, long_id]
        .iter()
        .for_each(|line| assert_eq!(parse_syslog(line.as_bytes(), YEAR), Err(ParseError::TooMuchStructuredData), "{line}"));
    Ok(())
}


#[test]
fn missing_priority_is_an_error() -> TestResult {
    let result = parse_syslog(b"Oct 11 22:14:15 mymachine su: hello", YEAR);
    assert!(result.is_err());
    Ok(())
}


proptest! {
    #[test]
    fn arbitrary_text_never_panics(text in ".{0,300}") {
        let _outcome = parse_syslog(text.as_bytes(), YEAR);
    }

    #[test]
    fn arbitrary_bytes_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..FUZZ_MAX_LEN)) {
        let _outcome = parse_syslog(&bytes, YEAR);
    }

    #[test]
    fn syslog_shaped_text_never_panics(text in "<[0-9]{1,3}>[0-9]? ?[A-Za-z0-9 :.\\[\\]=\"\\\\_@-]{0,200}") {
        let _outcome = parse_syslog(text.as_bytes(), YEAR);
    }
}
