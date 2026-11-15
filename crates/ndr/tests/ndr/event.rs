use crate::support::{field, fileinfo_line, now, TestResult, SHA_A};
use ndr::event::{match_event, parse_line, Parsed};
use ndr::model::Limits;
use ndr::model::Sighting;
use std::net::IpAddr;


fn limit() -> usize {
    Limits::default().max_line_bytes
}


#[test]
fn a_stored_fileinfo_line_becomes_a_sighting() -> TestResult {
    let expected = Sighting {
        sha256: SHA_A.to_string(),
        src_ip: Some("10.0.0.1".parse::<IpAddr>()?),
        dest_ip: Some("10.0.0.2".parse::<IpAddr>()?),
    };
    assert_eq!(parse_line(&fileinfo_line(SHA_A), limit()), Parsed::Stored(expected));
    Ok(())
}


#[test]
fn lines_that_are_not_stored_files_are_ignored() -> TestResult {
    assert_eq!(parse_line("{\"event_type\":\"alert\"}", limit()), Parsed::Ignored);
    let unstored = fileinfo_line(SHA_A).replace("true", "false");
    assert_eq!(parse_line(&unstored, limit()), Parsed::Ignored);
    let no_flag = format!("{{\"event_type\":\"fileinfo\",\"fileinfo\":{{\"sha256\":\"{SHA_A}\"}}}}");
    assert_eq!(parse_line(&no_flag, limit()), Parsed::Ignored);
    let other_type = fileinfo_line(SHA_A).replace("\"event_type\":\"fileinfo\"", "\"event_type\":\"http\"");
    assert_eq!(parse_line(&other_type, limit()), Parsed::Ignored);
    Ok(())
}


#[test]
fn hostile_lines_are_malformed() -> TestResult {
    assert_eq!(parse_line(&fileinfo_line(SHA_A), 1), Parsed::Malformed);
    assert_eq!(parse_line("\"fileinfo\" not json", limit()), Parsed::Malformed);
    assert_eq!(parse_line(&fileinfo_line("../../etc/shadow"), limit()), Parsed::Malformed);
    let no_hash = "{\"event_type\":\"fileinfo\",\"fileinfo\":{\"stored\":true}}";
    assert_eq!(parse_line(no_hash, limit()), Parsed::Malformed);
    let bad_ip = fileinfo_line(SHA_A).replace("10.0.0.1", "not an ip");
    assert_eq!(parse_line(&bad_ip, limit()), Parsed::Malformed);
    Ok(())
}


#[test]
fn a_match_event_names_hash_size_rule_and_endpoints_only() -> TestResult {
    let sighting = Sighting {
        sha256: SHA_A.to_string(),
        src_ip: Some("10.0.0.1".parse::<IpAddr>()?),
        dest_ip: None,
    };
    let json = serde_json::to_value(match_event(&sighting, FOUR_BYTES, "eicar", now()))?;
    assert_eq!(field(&json, "/rule/name"), Some("eicar"));
    assert_eq!(field(&json, "/file/hash/sha256"), Some(SHA_A));
    assert_eq!(json.pointer("/file/size").and_then(serde_json::Value::as_u64), Some(FOUR_BYTES));
    assert_eq!(field(&json, "/source/ip"), Some("10.0.0.1"));
    assert!(json.pointer("/destination").is_none());
    assert_eq!(field(&json, "/event/dataset"), Some("ndr.yara"));
    Ok(())
}


const FOUR_BYTES: u64 = 4;
