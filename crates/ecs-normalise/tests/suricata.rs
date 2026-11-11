#[path = "common/types.rs"]
mod types;


use ecs_normalise::cli::{log_dispatch, parse_format, run_reporting};
use ecs_normalise::convert::Outcome;
use ecs_normalise::error::NormaliseError;
use ecs_normalise::stream::{error_summary, normalise_stream_capped, normalise_stream_format, Counts, Format, MAX_LOG_ERROR_CHARS};
use ecs_normalise::suricata::{clean, clean_identity, is_unsafe, parse_eve, MAX_ANSWERS, MAX_FIELD_CHARS};
use ecs_normalise::suricata_extra::basename;
use serde_json::Value;
use std::io::Write;
use std::process::ExitCode;
use std::sync::{Arc, Mutex, PoisonError};
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use types::TestResult;


const CASES: [(&str, &str); 13] = [
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
    (
        include_str!("fixtures/suricata_fileinfo.json"),
        include_str!("snapshots/suricata_fileinfo.json"),
    ),
    (
        include_str!("fixtures/suricata_fileinfo_nohash.json"),
        include_str!("snapshots/suricata_fileinfo_nohash.json"),
    ),
    (include_str!("fixtures/suricata_smb.json"), include_str!("snapshots/suricata_smb.json")),
    (include_str!("fixtures/suricata_krb5.json"), include_str!("snapshots/suricata_krb5.json")),
    (
        include_str!("fixtures/suricata_krb5_error.json"),
        include_str!("snapshots/suricata_krb5_error.json"),
    ),
    (
        include_str!("fixtures/suricata_dcerpc.json"),
        include_str!("snapshots/suricata_dcerpc.json"),
    ),
    (
        include_str!("fixtures/suricata_alert_context.json"),
        include_str!("snapshots/suricata_alert_context.json"),
    ),
];


const STAMP: &str = "2026-11-10T19:00:00.123456+0000";


const CASE_COUNT: u64 = 13;


const LONG_URL: usize = 10_000;


const MANY_ANSWERS: usize = 1_000;


const HUGE_ANSWERS: usize = 100_000;


const SMALL_CAP: u64 = 128;


const BIG_CAP: u64 = 4_194_304;


const THREE: u64 = 3;


const TWO: u64 = 2;


const STATUS_70K: u64 = 70_000;


const BEYOND_U32: u64 = 4_294_967_296;


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
    let line = format!("{{\"timestamp\":\"{STAMP}\",\"event_type\":\"stats\"}}\n");
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
    assert_eq!(outcome, Outcome::Unknown("suricata:stats".to_string()));
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
    malformed(r#""event_type":"flow","src_port":"80","flow":{}"#)?;
    malformed(r#""event_type":"http","http":{"hostname":5}"#)?;
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
    ["alert", "flow", "dns", "http", "tls", "fileinfo", "smb", "krb5", "dcerpc"]
        .iter()
        .try_for_each(|kind| {
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


#[test]
fn a_hostile_status_never_drops_the_alert_or_the_http_line() -> TestResult {
    let alert = one(r#""event_type":"alert","alert":{"signature_id":7,"signature":"s","severity":4294967296},"http":{"status":70000,"hostname":5}"#)?;
    assert_eq!(text(&alert, "/rule/name"), Some("s"));
    assert_eq!(text(&alert, "/rule/id"), Some("7"));
    assert_eq!(text(&alert, "/labels/suricata_bad_alert_severity"), Some("4294967296"));
    let http = one(r#""event_type":"http","http":{"status":70000}"#)?;
    assert_eq!(http.pointer("/http/response/status_code").and_then(Value::as_u64), Some(STATUS_70K));
    let negative = one(r#""event_type":"http","http":{"status":-200}"#)?;
    assert_eq!(negative.pointer("/http/response/status_code"), None);
    assert_eq!(text(&negative, "/labels/suricata_bad_http_status"), Some("-200"));
    let big = one(r#""event_type":"http","http":{"status":4294967296,"length":-5}"#)?;
    assert_eq!(big.pointer("/http/response/status_code").and_then(Value::as_u64), Some(BEYOND_U32));
    assert_eq!(text(&big, "/labels/suricata_bad_http_length"), Some("-5"));
    let flow = one(r#""event_type":"flow","flow":{"bytes_toserver":-1,"pkts_toserver":"x","bytes_toclient":2,"pkts_toclient":3}"#)?;
    assert_eq!(text(&flow, "/labels/suricata_bad_flow_bytes_toserver"), Some("-1"));
    assert_eq!(text(&flow, "/labels/suricata_bad_flow_pkts_toserver"), Some("\"x\""));
    assert_eq!(flow.pointer("/destination/bytes").and_then(Value::as_u64), Some(TWO));
    Ok(())
}


#[test]
fn an_alert_line_ignores_its_other_objects_even_when_they_are_broken() -> TestResult {
    let alert = one(r#""event_type":"alert","alert":{"signature_id":1},"flow":5,"dns":[],"tls":"x","http":null"#)?;
    assert_eq!(text(&alert, "/rule/id"), Some("1"));
    Ok(())
}


#[test]
fn bidi_zero_width_and_separators_are_replaced_and_empty_text_is_left_out() -> TestResult {
    assert_eq!(
        clean("a\u{202E}b\u{200B}c\u{FEFF}d\u{2028}e\u{2066}f"),
        "a\u{FFFD}b\u{FFFD}c\u{FFFD}d\u{FFFD}e\u{FFFD}f"
    );
    assert!(!is_unsafe('a'));
    let http = one(r#""event_type":"http","http":{"hostname":"","http_user_agent":"x\u202ey"},"host":"","proto":"","in_iface":"""#)?;
    assert_eq!(http.pointer("/url"), None);
    assert_eq!(http.pointer("/host"), None);
    assert_eq!(http.pointer("/network"), None);
    assert_eq!(http.pointer("/labels"), None);
    assert_eq!(text(&http, "/user_agent/original"), Some("x\u{FFFD}y"));
    Ok(())
}


#[test]
fn a_malformed_line_logs_a_short_summary() -> TestResult {
    let huge = "x".repeat(WIDE_LINE * WIDE_LINE);
    let line = format!("{{\"timestamp\":\"{STAMP}\",\"event_type\":\"flow\",\"src_port\":\"{huge}\"}}");
    let error = parse_eve(&line).err().ok_or("expected an error")?;
    assert!(error.to_string().chars().count() > MAX_LOG_ERROR_CHARS);
    let summary = error_summary(&error);
    assert!(summary.chars().count() < MAX_LOG_ERROR_CHARS * TWO as usize);
    assert!(summary.contains("[cut, "));
    Ok(())
}


const BIG_NUMBER: &str = "18446744073709551616";


const HUGE_FIELD: usize = 500_000;


const SMB_NAME: usize = 10_000;


const SHARE_BYTES: usize = 1_048_576;


#[derive(Clone)]
struct SharedBuffer(Arc<Mutex<Vec<u8>>>);


impl Write for SharedBuffer {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}


#[test]
fn a_ten_thousand_character_smb_filename_is_cut_with_its_marker() -> TestResult {
    let name = "f".repeat(SMB_NAME);
    let value = one(&format!(
        "\"event_type\":\"smb\",\"smb\":{{\"command\":\"SMB2_COMMAND_CREATE\",\"filename\":\"{name}\"}}"
    ))?;
    let label = text(&value, "/labels/suricata_smb_filename").ok_or("no label")?;
    assert!(label.ends_with(&format!("[cut, {SMB_NAME} chars]")));
    assert_eq!(
        label.chars().count(),
        MAX_FIELD_CHARS + format!("[cut, {SMB_NAME} chars]").chars().count()
    );
    assert_eq!(text(&value, "/event/action"), Some("SMB2_COMMAND_CREATE"));
    Ok(())
}


#[test]
fn hostile_smb_names_and_shares_are_made_safe() -> TestResult {
    let value = one(r#""event_type":"smb","smb":{"filename":"a\u001b[31m\u0000b\u202ec","share":"\\\\h\u2028s","dialect":""}"#)?;
    assert_eq!(text(&value, "/labels/suricata_smb_filename"), Some("a\u{FFFD}[31m\u{FFFD}b\u{FFFD}c"));
    assert_eq!(text(&value, "/labels/suricata_smb_share"), Some("\\\\h\u{FFFD}s"));
    assert_eq!(value.pointer("/labels/suricata_smb_dialect"), None);
    let share = "s".repeat(SHARE_BYTES - SMB_NAME);
    let big = one(&format!("\"event_type\":\"smb\",\"smb\":{{\"share\":\"{share}\"}}"))?;
    assert!(text(&big, "/labels/suricata_smb_share").ok_or("no share")?.ends_with("chars]"));
    let minimal = one(r#""event_type":"smb","smb":{}"#)?;
    assert_eq!((minimal.pointer("/labels"), minimal.pointer("/event/action")), (None, None));
    Ok(())
}


#[test]
fn a_krb5_cname_cannot_pass_for_another_user() -> TestResult {
    let value = one("\"event_type\":\"krb5\",\"krb5\":{\"cname\":\"admin\\u202e\",\"error_code\":null}")?;
    assert_eq!(text(&value, "/user/name"), Some("admin\u{FFFD}"));
    assert_eq!(value.pointer("/event/outcome"), None);
    let zero_width = one("\"event_type\":\"krb5\",\"krb5\":{\"cname\":\"admin\\u200b\"}")?;
    assert_ne!(text(&zero_width, "/user/name"), Some("admin"));
    let numeric = one(r#""event_type":"krb5","krb5":{"error_code":6}"#)?;
    assert_eq!(text(&numeric, "/event/outcome"), Some("failure"));
    assert_eq!(numeric.pointer("/user"), None);
    let preauth_number = one(r#""event_type":"krb5","krb5":{"error_code":25}"#)?;
    let preauth_name = one(r#""event_type":"krb5","krb5":{"error_code":"KDC_ERR_PREAUTH_REQUIRED"}"#)?;
    let other_text = one(r#""event_type":"krb5","krb5":{"error_code":"KDC_ERR_PREAUTH_FAILED"}"#)?;
    assert_eq!(
        (preauth_number.pointer("/event/outcome"), preauth_name.pointer("/event/outcome")),
        (None, None)
    );
    assert_eq!(text(&other_text, "/event/outcome"), Some("failure"));
    Ok(())
}


#[test]
fn fileinfo_hashes_of_the_wrong_length_or_alphabet_become_labels() -> TestResult {
    let value = one(
        r#""event_type":"fileinfo","fileinfo":{"filename":"C:\\dir\\a.bin","md5":"abc","sha1":"zz39a3ee5e6b4b0d3255bfef95601890afd80709","sha256":"","state":"CLOSED","stored":null}"#,
    )?;
    assert_eq!(text(&value, "/labels/suricata_bad_fileinfo_md5"), Some("abc"));
    assert!(text(&value, "/labels/suricata_bad_fileinfo_sha1").is_some());
    assert_eq!(value.pointer("/file/hash"), None);
    assert_eq!(text(&value, "/file/name"), Some("a.bin"));
    assert_eq!(text(&value, "/file/path"), Some("C:\\dir\\a.bin"));
    assert_eq!(value.pointer("/labels/suricata_file_stored"), None);
    Ok(())
}


#[test]
fn fileinfo_names_and_sizes_edge_cases() -> TestResult {
    assert_eq!((basename("a/b"), basename("b"), basename("a\\b"), basename("dir/")), ("b", "b", "b", ""));
    let value = one(r#""event_type":"fileinfo","fileinfo":{"filename":"dir/","size":null}"#)?;
    assert_eq!((value.pointer("/file/name"), value.pointer("/file/size")), (None, None));
    assert_eq!(value.pointer("/labels/suricata_bad_fileinfo_size"), None);
    let bare = one(r#""event_type":"fileinfo","fileinfo":{}"#)?;
    assert_eq!(bare.pointer("/file"), None);
    Ok(())
}


#[test]
fn a_size_beyond_u64_is_kept_exactly() -> TestResult {
    let value = one(&format!("\"event_type\":\"fileinfo\",\"fileinfo\":{{\"size\":{BIG_NUMBER}}}"))?;
    assert_eq!(text(&value, "/labels/suricata_bad_fileinfo_size"), Some(BIG_NUMBER));
    assert_eq!(value.pointer("/file/size"), None);
    let flow = one(&format!(
        "\"event_type\":\"flow\",\"flow\":{{\"bytes_toserver\":{BIG_NUMBER},\"pkts_toclient\":1.5}}"
    ))?;
    assert_eq!(text(&flow, "/labels/suricata_bad_flow_bytes_toserver"), Some(BIG_NUMBER));
    assert_eq!(text(&flow, "/labels/suricata_bad_flow_pkts_toclient"), Some("1.5"));
    let null = one(r#""event_type":"flow","flow":{"bytes_toserver":null}"#)?;
    assert_eq!(null.pointer("/labels"), None);
    Ok(())
}


#[test]
fn dcerpc_actions_and_opnums() -> TestResult {
    let response = one(r#""event_type":"dcerpc","dcerpc":{"response":"RESPONSE","req":{"opnum":null}}"#)?;
    assert_eq!(text(&response, "/event/action"), Some("RESPONSE"));
    assert_eq!(response.pointer("/labels"), None);
    let bad = one(r#""event_type":"dcerpc","dcerpc":{"req":{"opnum":"x"},"interfaces":[{}]}"#)?;
    assert_eq!(text(&bad, "/labels/suricata_bad_dcerpc_opnum"), Some("\"x\""));
    let negative = one(r#""event_type":"dcerpc","dcerpc":{"req":{"opnum":-1},"interfaces":[]}"#)?;
    assert_eq!(text(&negative, "/labels/suricata_bad_dcerpc_opnum"), Some("-1"));
    let none = one(r#""event_type":"dcerpc","dcerpc":{"req":{}}"#)?;
    assert_eq!(none.pointer("/event/action"), None);
    Ok(())
}


#[test]
fn an_alert_keeps_hostile_context_leniently() -> TestResult {
    let alert = one(
        r#""event_type":"alert","alert":{"signature_id":9,"signature":"s"},"http":{"hostname":5,"url":"/a\u001bb","http_user_agent":["x"]},"tls":"x","dns":{"rrname":{"a":1}}"#,
    )?;
    assert_eq!(text(&alert, "/rule/id"), Some("9"));
    assert_eq!(text(&alert, "/url/original"), Some("/a\u{FFFD}b"));
    assert_eq!(text(&alert, "/labels/suricata_bad_alert_http_hostname"), Some("5"));
    assert_eq!(text(&alert, "/labels/suricata_bad_alert_http_http_user_agent"), Some("[\"x\"]"));
    assert_eq!(text(&alert, "/labels/suricata_bad_alert_tls"), Some("\"x\""));
    assert_eq!(text(&alert, "/labels/suricata_bad_alert_dns_rrname"), Some("{\"a\":1}"));
    assert_eq!(
        (alert.pointer("/tls"), alert.pointer("/dns"), alert.pointer("/user_agent")),
        (None, None, None)
    );
    let empty = one(r#""event_type":"alert","alert":{},"http":{"hostname":"","url":null},"tls":{},"dns":null"#)?;
    assert_eq!((empty.pointer("/url"), empty.pointer("/labels")), (None, None));
    Ok(())
}


#[test]
fn an_alert_with_a_500_kb_http_object_still_gives_one_alert() -> TestResult {
    let big = "h".repeat(HUGE_FIELD);
    let alert = one(&format!(
        "\"event_type\":\"alert\",\"alert\":{{\"signature_id\":1}},\"http\":{{\"hostname\":\"{big}\",\"x\":[{}]}}",
        vec!["1"; MANY_ANSWERS].join(",")
    ))?;
    assert_eq!(text(&alert, "/rule/id"), Some("1"));
    assert!(text(&alert, "/url/domain")
        .ok_or("no domain")?
        .ends_with(&format!("[cut, {HUGE_FIELD} chars]")));
    Ok(())
}


#[test]
fn an_own_object_that_is_not_an_object_is_malformed() -> TestResult {
    malformed(r#""event_type":"smb","smb":[]"#)?;
    malformed(r#""event_type":"smb","smb":5"#)?;
    Ok(())
}


#[test]
fn the_cli_log_shows_malformed_and_unknown_lines_at_warn() -> TestResult {
    let captured = SharedBuffer(Arc::new(Mutex::new(Vec::new())));
    let sink = captured.clone();
    let dispatch = log_dispatch(BoxMakeWriter::new(move || sink.clone()));
    let input = format!("not json\n{{\"timestamp\":\"{STAMP}\",\"event_type\":\"stats\"}}\n");
    tracing::dispatcher::with_default(&dispatch, || run(&input, BIG_CAP))?;
    let log = String::from_utf8(captured.0.lock().unwrap_or_else(PoisonError::into_inner).clone())?;
    assert!(log.contains("WARN"), "{log}");
    assert!(log.contains("suricata:stats"), "{log}");
    Ok(())
}


const INVISIBLE: &[char] = &[
    '\u{2060}',
    '\u{00AD}',
    '\u{200E}',
    '\u{200F}',
    '\u{061C}',
    '\u{E0041}',
    '\u{180E}',
    '\u{034F}',
    '\u{3164}',
    '\u{115F}',
    '\u{FE0F}',
    '\u{E0100}',
    '\u{FFA0}',
    '\u{E000}',
];


const LEGIT_TEXT: &str = "Zo\u{00EB} caf\u{00E9} e\u{0301}";


#[test]
fn no_invisible_character_lets_a_name_pass_for_another() -> TestResult {
    INVISIBLE.iter().try_for_each(|invisible| -> TestResult {
        assert!(is_unsafe(*invisible), "{invisible:?}");
        let krb5 = one(&format!("\"event_type\":\"krb5\",\"krb5\":{{\"cname\":\"admin{invisible}\"}}"))?;
        assert_eq!(text(&krb5, "/user/name"), Some("admin\u{FFFD}"));
        let smb = one(&format!("\"event_type\":\"smb\",\"smb\":{{\"filename\":\"admin{invisible}\"}}"))?;
        assert_eq!(text(&smb, "/labels/suricata_smb_filename"), Some("admin\u{FFFD}"));
        let http = one(&format!("\"event_type\":\"http\",\"http\":{{\"http_user_agent\":\"admin{invisible}\"}}"))?;
        assert_eq!(text(&http, "/user_agent/original"), Some("admin\u{FFFD}"));
        let alert = one(&format!(
            "\"event_type\":\"alert\",\"alert\":{{}},\"http\":{{\"http_user_agent\":\"admin{invisible}\"}}"
        ))?;
        assert_eq!(text(&alert, "/user_agent/original"), Some("admin\u{FFFD}"));
        Ok(())
    })?;
    assert_eq!(clean(LEGIT_TEXT), LEGIT_TEXT);
    Ok(())
}


#[test]
fn an_alert_dns_context_reads_the_suricata_7_query_list_and_the_flat_form() -> TestResult {
    let listed = one(r#""event_type":"alert","alert":{},"dns":{"query":[{"type":"query","rrname":"a.test","rrtype":"A"},{"rrname":"b.test"}]}"#)?;
    assert_eq!(text(&listed, "/dns/question/name"), Some("a.test"));
    let flat = one(r#""event_type":"alert","alert":{},"dns":{"rrname":"flat.test","query":[{"rrname":"b.test"}]}"#)?;
    assert_eq!(text(&flat, "/dns/question/name"), Some("flat.test"));
    let hostile = one(r#""event_type":"alert","alert":{},"dns":{"query":[{"rrname":7}]}"#)?;
    assert_eq!(text(&hostile, "/labels/suricata_bad_alert_dns_query_rrname"), Some("7"));
    let wrong = one(r#""event_type":"alert","alert":{},"dns":{"query":["x"]}"#)?;
    assert_eq!(text(&wrong, "/labels/suricata_bad_alert_dns_query"), Some("\"x\""));
    let nothing = one(r#""event_type":"alert","alert":{},"dns":{"query":[null]}"#)?;
    let empty_name = one(r#""event_type":"alert","alert":{},"dns":{"query":[{"rrname":null}]}"#)?;
    let empty_list = one(r#""event_type":"alert","alert":{},"dns":{"query":[]}"#)?;
    let null_query = one(r#""event_type":"alert","alert":{},"dns":{"query":null}"#)?;
    let no_query = one(r#""event_type":"alert","alert":{},"dns":{}"#)?;
    let blank = one(r#""event_type":"alert","alert":{},"dns":{"query":[{"rrname":""}]}"#)?;
    [nothing, empty_name, empty_list, blank, null_query, no_query]
        .iter()
        .for_each(|found| assert_eq!((found.pointer("/dns"), found.pointer("/labels")), (None, None)));
    Ok(())
}


#[test]
fn an_alert_dns_query_of_the_wrong_type_is_kept_as_a_label() -> TestResult {
    [("\"x\"", "\"x\""), ("5", "5"), (r#"{"rrname":"a.test"}"#, r#"{"rrname":"a.test"}"#)]
        .iter()
        .try_for_each(|(raw, shown)| -> TestResult {
            let value = one(&format!("\"event_type\":\"alert\",\"alert\":{{}},\"dns\":{{\"query\":{raw}}}"))?;
            assert_eq!(text(&value, "/labels/suricata_bad_alert_dns_query"), Some(*shown));
            assert_eq!(value.pointer("/dns"), None);
            Ok(())
        })
}


const BLANKS: &[char] = &[
    '\u{00A0}', '\u{1680}', '\u{2000}', '\u{2003}', '\u{200A}', '\u{202F}', '\u{205F}', '\u{3000}', '\u{2800}',
];


#[test]
fn a_blank_looking_character_cannot_make_an_identity_pass_for_another() -> TestResult {
    BLANKS.iter().chain([&' ']).try_for_each(|blank| -> TestResult {
        let krb5 = one(&format!("\"event_type\":\"krb5\",\"krb5\":{{\"cname\":\"admin{blank}\"}}"))?;
        assert_eq!(text(&krb5, "/user/name"), Some("admin\u{FFFD}"), "{blank:?}");
        let smb = one(&format!(
            "\"event_type\":\"smb\",\"smb\":{{\"filename\":\"admin{blank}\",\"share\":\"admin{blank}\"}}"
        ))?;
        assert_eq!(text(&smb, "/labels/suricata_smb_filename"), Some("admin\u{FFFD}"), "{blank:?}");
        assert_eq!(text(&smb, "/labels/suricata_smb_share"), Some("admin\u{FFFD}"), "{blank:?}");
        let host = one(&format!("\"event_type\":\"flow\",\"flow\":{{}},\"host\":\"admin{blank}\""))?;
        assert_eq!(text(&host, "/host/name"), Some("admin\u{FFFD}"), "{blank:?}");
        Ok(())
    })?;
    let inner = one(r#""event_type":"krb5","krb5":{"cname":"a b  "}"#)?;
    assert_eq!(text(&inner, "/user/name"), Some("a b\u{FFFD}\u{FFFD}"));
    assert_eq!(clean_identity("admin"), "admin");
    Ok(())
}


#[test]
fn a_duplicated_key_in_an_own_object_is_refused_for_every_number() -> TestResult {
    [
        r#""event_type":"alert","alert":{"signature_id":1,"signature_id":999}"#,
        r#""event_type":"alert","alert":{"severity":1,"severity":3}"#,
        r#""event_type":"flow","flow":{"pkts_toserver":1,"pkts_toserver":2}"#,
        r#""event_type":"flow","flow":{"pkts_toclient":1,"pkts_toclient":2}"#,
        r#""event_type":"flow","flow":{"bytes_toserver":1,"bytes_toserver":2}"#,
        r#""event_type":"flow","flow":{"bytes_toclient":1,"bytes_toclient":2}"#,
        r#""event_type":"http","http":{"status":200,"status":404}"#,
        r#""event_type":"http","http":{"length":1,"length":2}"#,
        r#""event_type":"fileinfo","fileinfo":{"filename":"/x","size":1,"size":999}"#,
        r#""event_type":"dcerpc","dcerpc":{"req":{"opnum":1,"opnum":2}}"#,
        r#""event_type":"krb5","krb5":{"error_code":null,"error_code":25}"#,
        r#""event_type":"smb","smb":{"share":"a","share":"b"}"#,
    ]
    .iter()
    .try_for_each(|body| malformed(body))
}


#[test]
fn a_stored_flag_and_a_huge_opnum_are_kept_as_text() -> TestResult {
    let flag = one(r#""event_type":"fileinfo","fileinfo":{"stored":true}"#)?;
    assert_eq!(text(&flag, "/labels/suricata_file_stored"), Some("true"));
    let name = one(r#""event_type":"fileinfo","fileinfo":{"stored":"/var/x"}"#)?;
    assert_eq!(text(&name, "/labels/suricata_file_stored"), Some("/var/x"));
    let opnum = one(r#""event_type":"dcerpc","dcerpc":{"req":{"opnum":18446744073709551616}}"#)?;
    assert_eq!(text(&opnum, "/labels/suricata_bad_dcerpc_opnum"), Some(BIG_NUMBER));
    let good = one(r#""event_type":"dcerpc","dcerpc":{"req":{"opnum":15}}"#)?;
    assert_eq!(text(&good, "/labels/suricata_dcerpc_opnum"), Some("15"));
    Ok(())
}
