use crate::common::types::TestResult;
use connector_manifest::error::ConnectorError;
use connector_manifest::reply::{parse_reply, scan_reply, Reply, MAX_REPLY_BYTES, MAX_REPLY_DEPTH, MAX_REPLY_ELEMENTS, MAX_REPLY_STRING_BYTES};


const HALF: usize = 2;


const DOUBLE: usize = 2;


fn bound_of(bytes: &[u8]) -> Result<&'static str, Box<dyn std::error::Error>> {
    match parse_reply(bytes) {
        Err(ConnectorError::ReplyBound { bound }) => Ok(bound),
        other => Err(format!("expected a bound, got {other:?}").into()),
    }
}


fn malformed(bytes: &[u8]) -> TestResult {
    assert!(
        matches!(parse_reply(bytes), Err(ConnectorError::MalformedReply)),
        "{}",
        String::from_utf8_lossy(bytes)
    );
    Ok(())
}


#[test]
fn a_success_and_a_failure_follow_the_grammar() -> TestResult {
    let success = parse_reply(br#"{"status":"ok","result":{"a":[1,2,{"b":"c"}]}}"#)?;
    assert!(matches!(&success, Reply::Success { result: Some(value) } if value.get() == r#"{"a":[1,2,{"b":"c"}]}"#));
    assert!(matches!(parse_reply(br#"{"status":"ok"}"#)?, Reply::Success { result: None }));
    assert!(matches!(
        parse_reply(br#"{"status":"ok","result":null}"#)?,
        Reply::Success { result: None }
    ));
    let failure = parse_reply(br#"{"status":"error","error":"not-found"}"#)?;
    assert!(matches!(&failure, Reply::Failure { code } if code == "not-found"));
    Ok(())
}


#[test]
fn every_other_shape_is_malformed_without_a_serde_error() -> TestResult {
    malformed(b"")?;
    malformed(b"[]")?;
    malformed(b"not json")?;
    malformed(br#"{"status":"maybe"}"#)?;
    malformed(br#"{"status":"ok","extra":1}"#)?;
    malformed(br#"{"status":"ok","status":"ok"}"#)?;
    malformed(br#"{"status":"ok","error":"x"}"#)?;
    malformed(br#"{"status":"error"}"#)?;
    malformed(br#"{"status":"error","error":"Bad Code"}"#)?;
    malformed(br#"{"status":"error","error":"-x"}"#)?;
    malformed(br#"{"status":"error","error":"x","result":1}"#)?;
    malformed(br#"{"status":"ok"} trailing"#)?;
    let refusal = format!("{:?}", parse_reply(br#"{"status":"ok","secret-marker":1}"#));
    assert!(!refusal.contains("secret-marker"), "{refusal}");
    Ok(())
}


#[test]
fn a_reply_over_the_byte_cap_is_refused_whole() -> TestResult {
    let big = vec![b' '; MAX_REPLY_BYTES + 1];
    assert!(matches!(parse_reply(&big), Err(ConnectorError::ReplyTooLarge { max }) if max == MAX_REPLY_BYTES));
    let exact = format!(r#"{{"status":"ok"}}{}"#, " ".repeat(MAX_REPLY_BYTES - r#"{"status":"ok"}"#.len()));
    assert!(matches!(parse_reply(exact.as_bytes())?, Reply::Success { .. }));
    Ok(())
}


#[test]
fn ten_million_elements_under_the_byte_cap_are_refused_before_any_value_is_built() -> TestResult {
    let flat = format!(r#"{{"status":"ok","result":[{}0]}}"#, "0,".repeat(MAX_REPLY_ELEMENTS));
    assert_eq!(bound_of(flat.as_bytes())?, "elements");
    let nested = format!(
        r#"{{"status":"ok","result":[{}]}}"#,
        "[0,0,0,0,0,0,0,0],".repeat(MAX_REPLY_ELEMENTS / HALF) + "0"
    );
    assert_eq!(bound_of(nested.as_bytes())?, "elements");
    let objects = format!(
        r#"{{"status":"ok","result":{{{}"z":0}}}}"#,
        r#""a":{"b":[0,0,0]},"#.repeat(MAX_REPLY_ELEMENTS)
    );
    assert_eq!(bound_of(objects.as_bytes())?, "elements");
    let ok = format!(r#"{{"status":"ok","result":[{}0]}}"#, "0,".repeat(MAX_REPLY_ELEMENTS / HALF));
    parse_reply(ok.as_bytes())?;
    Ok(())
}


#[test]
fn deep_nesting_is_refused_by_the_scan_and_the_depth_cap_is_inclusive() -> TestResult {
    let deep = format!("{}{}", "[".repeat(MAX_REPLY_DEPTH + 1), "]".repeat(MAX_REPLY_DEPTH + 1));
    assert_eq!(bound_of(format!(r#"{{"status":"ok","result":{deep}}}"#).as_bytes())?, "nesting depth");
    let allowed = format!("{}{}", "[".repeat(MAX_REPLY_DEPTH - 1), "]".repeat(MAX_REPLY_DEPTH - 1));
    parse_reply(format!(r#"{{"status":"ok","result":{allowed}}}"#).as_bytes())?;
    let unbalanced = "]".repeat(MAX_REPLY_DEPTH * DOUBLE);
    scan_reply(unbalanced.as_bytes())?;
    Ok(())
}


#[test]
fn a_string_over_its_cap_is_refused_and_escapes_and_quotes_inside_strings_do_not_count_as_structure() -> TestResult {
    let long = format!(r#"{{"status":"ok","result":"{}"}}"#, "a".repeat(MAX_REPLY_STRING_BYTES + 1));
    assert_eq!(bound_of(long.as_bytes())?, "string length");
    let at_cap = format!(r#"{{"status":"ok","result":"{}"}}"#, "a".repeat(MAX_REPLY_STRING_BYTES));
    parse_reply(at_cap.as_bytes())?;
    let escaped = format!(r#"{{"status":"ok","result":"{}"}}"#, r#"\"[{,"#.repeat(MAX_REPLY_ELEMENTS));
    parse_reply(escaped.as_bytes())?;
    let reset = format!(
        r#"{{"status":"ok","result":["{}","{}"]}}"#,
        "a".repeat(MAX_REPLY_STRING_BYTES),
        "b".repeat(MAX_REPLY_STRING_BYTES)
    );
    parse_reply(reset.as_bytes())?;
    let slash_quote = format!(r#"{{"status":"ok","result":"{}"}}"#, r#"\\"#.repeat(MAX_REPLY_ELEMENTS));
    parse_reply(slash_quote.as_bytes())?;
    Ok(())
}
