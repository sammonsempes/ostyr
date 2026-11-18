use crate::common::{completion, reply, Failing, MARKER, NODE_CAP};
use crate::numbers::{SEPARATORS_COUNTED, SMALL_CAP};
use crate::types::TestResult;
use ai_gateway::error::AiError;
use ai_gateway::limits::STATUS_OK;
use ai_gateway::model::HttpReply;
use ai_gateway::response::{malformed, parse_answer, read_body, scan_byte, ScanState};
use std::io::Cursor;


#[test]
fn the_scan_ignores_separators_inside_strings() -> TestResult {
    let quoted = br#"{"a":"[[[,,,{{{\" [[[ ","b":1}"#;
    let end = quoted.iter().try_fold(ScanState::default(), |state, byte| scan_byte(state, *byte))?;
    assert_eq!(end.weight, SEPARATORS_COUNTED);
    assert!(!end.in_string);
    Ok(())
}


#[test]
fn the_scan_refuses_past_the_cap_and_reads_the_whole_body_below_it() -> TestResult {
    let below = vec![b'['; NODE_CAP];
    assert!(below.iter().try_fold(ScanState::default(), |state, byte| scan_byte(state, *byte)).is_ok());
    let above = vec![b'['; NODE_CAP + 1];
    let error = above
        .iter()
        .try_fold(ScanState::default(), |state, byte| scan_byte(state, *byte))
        .err()
        .ok_or("accepted")?;
    assert!(matches!(error, AiError::TooManyNodes { cap } if cap == NODE_CAP));
    assert!(matches!(parse_answer(&above), Err(AiError::TooManyNodes { .. })));
    Ok(())
}


#[test]
fn a_parse_error_keeps_only_a_position() -> TestResult {
    let source = serde_json::from_str::<serde_json::Value>(&format!("\"{MARKER}")).err().ok_or("parsed")?;
    let error = malformed(source);
    assert!(matches!(error, AiError::Malformed { line: 1, .. }));
    assert!(!format!("{error} {error:?}").contains(MARKER));
    Ok(())
}


#[test]
fn the_body_is_read_up_to_one_byte_past_the_cap() -> TestResult {
    let body = |bytes: Vec<u8>| HttpReply {
        status: STATUS_OK,
        body: Box::new(Cursor::new(bytes)),
    };
    assert_eq!(read_body(body(vec![b'a'; SMALL_CAP]), SMALL_CAP)?.len(), SMALL_CAP);
    assert!(matches!(
        read_body(body(vec![b'a'; SMALL_CAP + 1]), SMALL_CAP),
        Err(AiError::ResponseTooLarge { cap: SMALL_CAP })
    ));
    let failing = HttpReply {
        status: STATUS_OK,
        body: Box::new(Failing),
    };
    assert!(matches!(read_body(failing, SMALL_CAP), Err(AiError::Io { .. })));
    assert_eq!(parse_answer(&completion("x"))?.content, "x");
    assert!(reply_is_ok());
    Ok(())
}


fn reply_is_ok() -> bool {
    reply(STATUS_OK, Vec::new()).is_ok()
}


#[test]
fn every_counted_byte_is_refused_at_the_cap() -> TestResult {
    let full = ScanState {
        weight: NODE_CAP,
        ..ScanState::default()
    };
    b"[{,"
        .iter()
        .for_each(|byte| assert!(matches!(scan_byte(full, *byte), Err(AiError::TooManyNodes { .. }))));
    assert!(scan_byte(full, b'x').is_ok());
    Ok(())
}
