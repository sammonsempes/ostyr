use crate::support::{fixture, MAY_WRITE, SMALL_CAP};
use crate::types::TestResult;
use linux_fim::classify::{classify, escape_field};
use linux_fim::limits::{MAX_EVENT_LINE_BYTES, MAX_FIELD_BYTES};
use linux_fim::model::FimEvent;
use serde_json::json;


const BIG_LINE: usize = 65_536;


const OVER_FIELD: usize = 2000;


fn kprobe_line(policy: &str, function: &str, args: &serde_json::Value, process: &serde_json::Value) -> String {
    json!({"process_kprobe": {"policy_name": policy, "function_name": function, "args": args, "process": process}}).to_string()
}


fn write_line(path: &str) -> String {
    kprobe_line(
        "ostyr-fim-server",
        "security_file_permission",
        &json!([{"file_arg": {"path": path}}, {"int_arg": MAY_WRITE}]),
        &json!({"binary": "/usr/bin/tee"}),
    )
}


#[test]
fn a_captured_write_to_passwd_is_a_write() -> TestResult {
    assert_eq!(
        classify(&fixture("write-passwd.json")?, MAX_EVENT_LINE_BYTES),
        Some(FimEvent::Write {
            path: "/etc/passwd".to_string(),
            process: "/usr/bin/tee".to_string()
        })
    );
    Ok(())
}


#[test]
fn a_captured_write_to_a_unit_is_a_write() -> TestResult {
    assert!(matches!(
        classify(&fixture("write-unit.json")?, MAX_EVENT_LINE_BYTES),
        Some(FimEvent::Write { path, .. }) if path == "/etc/systemd/system/x.service"
    ));
    Ok(())
}


#[test]
fn a_captured_creation_reports_the_directory() -> TestResult {
    assert!(matches!(
        classify(&fixture("create-cron.json")?, MAX_EVENT_LINE_BYTES),
        Some(FimEvent::Write { path, process }) if path == "/etc/cron.d" && process == "/usr/bin/touch"
    ));
    Ok(())
}


#[test]
fn a_captured_open_of_a_canary_is_a_honeytoken_event() -> TestResult {
    assert_eq!(
        classify(&fixture("open-canary.json")?, MAX_EVENT_LINE_BYTES),
        Some(FimEvent::Honeytoken {
            path: "/var/backups/.canary".to_string(),
            process: "/usr/bin/cat".to_string()
        })
    );
    Ok(())
}


#[test]
fn an_unrelated_event_is_none() -> TestResult {
    assert_eq!(classify(&fixture("process-exec.json")?, MAX_EVENT_LINE_BYTES), None);
    Ok(())
}


#[test]
fn a_kprobe_of_another_policy_is_none() -> TestResult {
    let line = fixture("write-passwd.json")?.replace("ostyr-fim-server", "other-policy");
    assert_eq!(classify(&line, MAX_EVENT_LINE_BYTES), None);
    Ok(())
}


#[test]
fn a_kprobe_of_an_unknown_function_is_none() -> TestResult {
    let line = kprobe_line(
        "ostyr-fim-a",
        "security_inode_unlink",
        &json!([{"file_arg": {"path": "/etc/passwd"}}]),
        &json!({}),
    );
    assert_eq!(classify(&line, MAX_EVENT_LINE_BYTES), None);
    Ok(())
}


#[test]
fn a_kprobe_without_policy_function_or_path_is_none() -> TestResult {
    let no_policy = json!({"process_kprobe": {"function_name": "security_file_open", "args": [{"file_arg": {"path": "/a"}}]}}).to_string();
    let no_function = json!({"process_kprobe": {"policy_name": "ostyr-fim-a", "args": [{"file_arg": {"path": "/a"}}]}}).to_string();
    let no_args = json!({"process_kprobe": {"policy_name": "ostyr-fim-a", "function_name": "security_file_open"}}).to_string();
    let no_path = kprobe_line(
        "ostyr-fim-a",
        "security_file_open",
        &json!([{"int_arg": 1}, {"file_arg": {}}]),
        &json!({}),
    );
    assert!([no_policy, no_function, no_args, no_path]
        .iter()
        .all(|line| classify(line, MAX_EVENT_LINE_BYTES).is_none()));
    Ok(())
}


#[test]
fn the_first_argument_with_a_path_wins() -> TestResult {
    let line = kprobe_line(
        "ostyr-fim-a",
        "security_file_permission",
        &json!([{"int_arg": 1}, {"path_arg": {"path": "/etc/shadow"}}, {"file_arg": {"path": "/etc/passwd"}}]),
        &json!({"binary": "/bin/x"}),
    );
    assert!(matches!(classify(&line, MAX_EVENT_LINE_BYTES), Some(FimEvent::Write { path, .. }) if path == "/etc/shadow"));
    Ok(())
}


#[test]
fn a_missing_process_is_unknown_not_dropped() -> TestResult {
    let no_process =
        json!({"process_kprobe": {"policy_name": "ostyr-fim-a", "function_name": "security_file_open", "args": [{"file_arg": {"path": "/a"}}]}})
            .to_string();
    let no_binary = kprobe_line(
        "ostyr-fim-a",
        "security_file_open",
        &json!([{"file_arg": {"path": "/a"}}]),
        &json!({"pid": 1}),
    );
    assert!([no_process, no_binary]
        .iter()
        .all(|line| matches!(classify(line, MAX_EVENT_LINE_BYTES), Some(FimEvent::Honeytoken { process, .. }) if process == "unknown")));
    Ok(())
}


#[test]
fn an_oversized_line_is_none() -> TestResult {
    let line = write_line("/etc/passwd");
    assert!(classify(&line, line.len()).is_some());
    assert_eq!(classify(&line, line.len() - 1), None);
    assert_eq!(classify(&write_line(&"a".repeat(BIG_LINE)), MAX_EVENT_LINE_BYTES), None);
    Ok(())
}


#[test]
fn invalid_json_and_wrong_shapes_are_none() -> TestResult {
    let lines = [
        "",
        "not json",
        "{",
        "[]",
        "{\"process_kprobe\": 7}",
        "{\"process_kprobe\": {\"args\": 7}}",
    ];
    assert!(lines.iter().all(|line| classify(line, MAX_EVENT_LINE_BYTES).is_none()));
    Ok(())
}


#[test]
fn control_characters_are_escaped_in_the_path() -> TestResult {
    let line = write_line("/etc/x \u{1b}[31m\n\u{202e}é\\");
    assert!(matches!(
        classify(&line, MAX_EVENT_LINE_BYTES),
        Some(FimEvent::Write { path, .. }) if path == "/etc/x \\u{1b}[31m\\n\\u{202e}\\u{e9}\\\\"
    ));
    Ok(())
}


#[test]
fn a_long_path_is_cut_with_a_visible_marker() -> TestResult {
    let cut = escape_field(&"a".repeat(OVER_FIELD));
    assert_eq!(
        cut,
        format!("{}[cut {} bytes]", "a".repeat(MAX_FIELD_BYTES), OVER_FIELD - MAX_FIELD_BYTES)
    );
    let exact = "a".repeat(MAX_FIELD_BYTES);
    assert_eq!(escape_field(&exact), exact);
    Ok(())
}


#[test]
fn escapes_are_counted_in_the_cap() -> TestResult {
    let escaped = escape_field(&"\u{1}".repeat(SMALL_CAP * MAX_FIELD_BYTES));
    assert!(escaped.starts_with("\\u{1}"));
    assert!(escaped.ends_with(" bytes]"));
    Ok(())
}
