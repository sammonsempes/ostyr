#[path = "common/types.rs"]
mod types;


use ecs_normalise::cli::{parse_format, run_reporting};
use ecs_normalise::convert::Outcome;
use ecs_normalise::error::NormaliseError;
use ecs_normalise::stream::{normalise_stream_capped, normalise_stream_format, Counts, Format};
use ecs_normalise::suricata::{clean, parse_eve, MAX_ANSWERS, MAX_FIELD_CHARS};
use serde_json::Value;
use std::process::ExitCode;
use types::TestResult;


const CASES: [(&str, &str); 6] = [
    (
        include_str!("fixtures/suricata_alert.json"),
        include_str!("snapshots/suricata_alert.json"),
    ),
    (include_str!("fixtures/suricata_flow.json"), include_str!("snapshots/suricata_flow.json")),
    (
        include_str!("fixtures/suricata_dns_v2.json"),
        include_str!("snapshots/suricata_dns_v2.json"),
    ),
    (
        include_str!("fixtures/suricata_dns_v3.json"),
        include_str!("snapshots/suricata_dns_v3.json"),
    ),
    (include_str!("fixtures/suricata_http.json"), include_str!("snapshots/suricata_http.json")),
    (include_str!("fixtures/suricata_tls.json"), include_str!("snapshots/suricata_tls.json")),
];


const STAMP: &str = "2026-11-10T19:00:00.123456+0000";


const CASE_COUNT: u64 = 6;


const LONG_URL: usize = 10_000;


const MANY_ANSWERS: usize = 1_000;


const HUGE_ANSWERS: usize = 100_000;


const SMALL_CAP: u64 = 128;


const BIG_CAP: u64 = 4_194_304;


const THREE: u64 = 3;


const WIDE_LINE: usize = 200;


const DEEP: usize = 5_000;


fn run(input: &str, cap: u64) -> Result<(String, Counts), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let mut reader = input.as_bytes();
    let counts = normalise_stream_capped(&mut reader, &mut out, cap, Format::Suricata)?;
    Ok((String::from_utf8(out)?, counts))
}


fn one(body: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let line = format!("{{\"timestamp\":\"{STAMP}\",{body}}}\n");
    let (out, counts) = run(&line, BIG_CAP)?;
    assert_eq!(counts.processed, 1, "{out}");
    Ok(serde_json::from_str(&out)?)
}


fn malformed(body: &str) -> Result<(), Box<dyn std::error::Error>> {
    let line = format!("{{\"timestamp\":\"{STAMP}\",{body}}}\n");
    let (out, counts) = run(&line, BIG_CAP)?;
    assert_eq!((out.as_str(), counts.malformed, counts.processed), ("", 1, 0));
    Ok(())
}


fn text<'a>(value: &'a Value, pointer: &str) -> Option<&'a str> {
    value.pointer(pointer).and_then(Value::as_str)
}


#[test]
fn every_fixture_gives_its_snapshot() -> TestResult {
    let input: String = CASES.iter().map(|(fixture, _)| fixture.to_string()).collect();
    let mut out = Vec::new();
    let mut reader = input.as_bytes();
    let counts = normalise_stream_format(&mut reader, &mut out, Format::Suricata)?;
    let expected: String = CASES.iter().map(|(_, snapshot)| snapshot.to_string()).collect();
    assert_eq!(String::from_utf8(out)?, expected);
    assert_eq!(
        counts,
        Counts {
            processed: CASE_COUNT,
            ..Counts::default()
        }
    );
    Ok(())
}


#[test]
fn an_unmapped_event_type_is_counted_and_not_written() -> TestResult {
    let line = format!("{{\"timestamp\":\"{STAMP}\",\"event_type\":\"smb\"}}\n");
    let (out, counts) = run(&line, BIG_CAP)?;
    assert_eq!(out, "");
    assert_eq!(
        counts,
        Counts {
            unknown: 1,
            ..Counts::default()
        }
    );
    let outcome = parse_eve(line.trim())?;
    assert_eq!(outcome, Outcome::Unknown("suricata:smb".to_string()));
    Ok(())
}


#[test]
fn an_unmapped_event_type_name_is_cleaned() -> TestResult {
    let line = format!("{{\"timestamp\":\"{STAMP}\",\"event_type\":\"a\\u001b[31m\"}}");
    assert_eq!(parse_eve(&line)?, Outcome::Unknown("suricata:a\u{FFFD}[31m".to_string()));
    Ok(())
}


#[test]
fn out_of_range_numbers_and_wrong_types_are_malformed() -> TestResult {
    malformed(r#""event_type":"flow","src_port":70000,"flow":{}"#)?;
    malformed(r#""event_type":"flow","flow":{"bytes_toserver":-1}"#)?;
    malformed(r#""event_type":"flow","src_port":"80","flow":{}"#)?;
    malformed(r#""event_type":"http","http":{"hostname":5}"#)?;
    malformed(r#""event_type":"http","http":{"status":70000}"#)?;
    malformed(r#""event_type":"flow","src_ip":"not an address","flow":{}"#)?;
    malformed(r#""event_type":"flow","flow":{"start":"yesterday"}"#)?;
    malformed(r#""event_type":5"#)?;
    Ok(())
}


#[test]
fn a_bad_timestamp_or_bad_json_is_malformed() -> TestResult {
    let input = "{\"timestamp\":\"2026-11-10 19:00:00\",\"event_type\":\"flow\",\"flow\":{}}\nnot json\n{\"event_type\":\"flow\"}\n";
    let (out, counts) = run(input, BIG_CAP)?;
    assert_eq!(out, "");
    assert_eq!(counts.malformed, THREE);
    assert!(matches!(parse_eve("not json"), Err(NormaliseError::Syntax(_))));
    assert!(matches!(parse_eve("[]"), Err(NormaliseError::Schema(_))));
    Ok(())
}


#[test]
fn a_duplicate_event_type_keeps_the_last_one() -> TestResult {
    let value = one(r#""event_type":"flow","event_type":"dns","dns":{}"#)?;
    assert_eq!(text(&value, "/event/dataset"), Some("suricata.dns"));
    Ok(())
}


#[test]
fn a_missing_object_is_a_missing_field() -> TestResult {
    ["alert", "flow", "dns", "http", "tls"].iter().try_for_each(|kind| {
        let line = format!("{{\"timestamp\":\"{STAMP}\",\"event_type\":\"{kind}\"}}");
        assert!(matches!(parse_eve(&line), Err(NormaliseError::MissingField(name)) if name == *kind));
        Ok::<(), NormaliseError>(())
    })?;
    Ok(())
}


#[test]
fn a_long_url_is_cut_with_a_marker() -> TestResult {
    let url = format!("/{}", "a".repeat(LONG_URL));
    let value = one(&format!("\"event_type\":\"http\",\"http\":{{\"url\":\"{url}\"}}"))?;
    let original = text(&value, "/url/original").ok_or("no url")?;
    assert_eq!(
        original.chars().count(),
        MAX_FIELD_CHARS + format!("[cut, {} chars]", LONG_URL + 1).chars().count()
    );
    assert!(original.ends_with(&format!("[cut, {} chars]", LONG_URL + 1)));
    Ok(())
}


#[test]
fn control_characters_are_replaced() -> TestResult {
    let value = one(r#""event_type":"tls","tls":{"sni":"a\u0000b\u001b[31mc"},"host":"h\n1""#)?;
    assert_eq!(text(&value, "/tls/client/server_name"), Some("a\u{FFFD}b\u{FFFD}[31mc"));
    assert_eq!(text(&value, "/host/name"), Some("h\u{FFFD}1"));
    assert_eq!(clean("plain"), "plain");
    Ok(())
}


#[test]
fn a_thousand_answers_keep_the_cap_and_the_omitted_count() -> TestResult {
    let answers = vec![r#"{"rdata":"10.0.0.1"}"#; MANY_ANSWERS].join(",");
    let value = one(&format!("\"event_type\":\"dns\",\"dns\":{{\"answers\":[{answers}]}}"))?;
    let kept = value.pointer("/dns/resolved_ip").and_then(Value::as_array).map(Vec::len);
    assert_eq!(kept, Some(MAX_ANSWERS));
    assert_eq!(
        text(&value, "/labels/dns_answers_omitted"),
        Some((MANY_ANSWERS - MAX_ANSWERS).to_string().as_str())
    );
    Ok(())
}


#[test]
fn a_hundred_thousand_empty_answers_stay_within_the_line() -> TestResult {
    let answers = vec!["{}"; HUGE_ANSWERS].join(",");
    let value = one(&format!("\"event_type\":\"dns\",\"dns\":{{\"answers\":[{answers}]}}"))?;
    assert_eq!(
        text(&value, "/labels/dns_answers_omitted"),
        Some((HUGE_ANSWERS - MAX_ANSWERS).to_string().as_str())
    );
    assert_eq!(value.pointer("/dns/resolved_ip"), None);
    Ok(())
}


#[test]
fn deeply_nested_json_is_malformed_not_a_crash() -> TestResult {
    let nested = format!("{}{}", "[".repeat(DEEP), "]".repeat(DEEP));
    let line = format!("{{\"timestamp\":\"{STAMP}\",\"event_type\":\"flow\",\"flow\":{{\"x\":{nested}}}}}\n");
    let (_, counts) = run(&line, BIG_CAP)?;
    assert_eq!(counts.malformed, 1);
    Ok(())
}


#[test]
fn a_line_over_the_cap_is_malformed_and_the_next_one_is_read() -> TestResult {
    let long = format!("{{\"timestamp\":\"{STAMP}\",\"event_type\":\"{}\"}}\n", "x".repeat(WIDE_LINE));
    let short = format!("{{\"timestamp\":\"{STAMP}\",\"event_type\":\"dns\",\"dns\":{{}}}}\n");
    let (out, counts) = run(&format!("{long}{short}"), SMALL_CAP)?;
    assert_eq!((counts.malformed, counts.processed), (1, 1));
    assert_eq!(out.lines().count(), 1);
    Ok(())
}


#[test]
fn minimal_events_leave_out_every_empty_group() -> TestResult {
    let flow = one(r#""event_type":"flow","flow":{}"#)?;
    assert_eq!(flow.pointer("/source"), None);
    assert_eq!(flow.pointer("/network"), None);
    assert_eq!(flow.pointer("/host"), None);
    let http = one(r#""event_type":"http","http":{}"#)?;
    assert_eq!(
        (http.pointer("/url"), http.pointer("/http"), http.pointer("/user_agent")),
        (None, None, None)
    );
    let tls = one(r#""event_type":"tls","tls":{"ja3":{},"ja3s":{"hash":"x"}}"#)?;
    assert_eq!(text(&tls, "/tls/server/ja3s/hash"), Some("x"));
    assert_eq!(tls.pointer("/tls/client"), None);
    let alert = one(r#""event_type":"alert","alert":{}"#)?;
    assert_eq!((alert.pointer("/rule"), text(&alert, "/event/kind")), (None, Some("alert")));
    let dns = one(r#""event_type":"dns","dns":{"queries":[{"rrname":"q.test","rrtype":"TXT"}],"rdata":"::1"}"#)?;
    assert_eq!(text(&dns, "/dns/question/name"), Some("q.test"));
    assert_eq!(text(&dns, "/dns/question/type"), Some("TXT"));
    assert_eq!(text(&dns, "/dns/resolved_ip/0"), Some("::1"));
    Ok(())
}


#[test]
fn the_format_is_selected_by_name_and_reports_three_counts() -> TestResult {
    assert_eq!(parse_format(&["--format", "suricata"])?, Format::Suricata);
    let mut out = Vec::new();
    let mut err = Vec::new();
    let mut input = CASES.first().map(|(fixture, _)| fixture.as_bytes()).ok_or("no case")?;
    let code = run_reporting(&["--format", "suricata"], &mut input, &mut out, &mut err)?;
    assert_eq!(code, ExitCode::SUCCESS);
    assert_eq!(String::from_utf8(err)?, "processed=1 malformed=0 unknown=0\n");
    Ok(())
}
