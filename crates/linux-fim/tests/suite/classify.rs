use crate::support::{fixture, MAY_WRITE, SMALL_CAP};
use crate::types::TestResult;
use linux_fim::classify::{classify, escape_field};
use linux_fim::limits::{MAX_EVENT_LINE_BYTES, MAX_FIELD_BYTES};
use linux_fim::model::FimEvent;
use serde_json::json;


const BIG_LINE: usize = 65_536;


const PADDED_BYTES: usize = 201_041;


const SMALL_LINE_CAP: usize = 10;


const OVER_HARD_CAP: usize = 5_000_000;


fn policies() -> Vec<String> {
    ["ostyr-fim-server", "ostyr-fimn-server", "ostyr-fim-a"].map(String::from).to_vec()
}


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
        classify(&fixture("write-passwd.json")?, MAX_EVENT_LINE_BYTES, &policies()),
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
        classify(&fixture("write-unit.json")?, MAX_EVENT_LINE_BYTES, &policies()),
        Some(FimEvent::Write { path, .. }) if path == "/etc/systemd/system/x.service"
    ));
    Ok(())
}


#[test]
fn a_captured_creation_reports_the_directory() -> TestResult {
    assert!(matches!(
        classify(&fixture("create-cron.json")?, MAX_EVENT_LINE_BYTES, &policies()),
        Some(FimEvent::Write { path, process }) if path == "/etc/cron.d" && process == "/usr/bin/touch"
    ));
    Ok(())
}


#[test]
fn a_captured_open_of_a_canary_is_a_honeytoken_event() -> TestResult {
    assert_eq!(
        classify(&fixture("open-canary.json")?, MAX_EVENT_LINE_BYTES, &policies()),
        Some(FimEvent::Honeytoken {
            path: "/var/backups/.canary".to_string(),
            process: "/usr/bin/cat".to_string()
        })
    );
    Ok(())
}


#[test]
fn an_unrelated_event_is_none() -> TestResult {
    assert_eq!(classify(&fixture("process-exec.json")?, MAX_EVENT_LINE_BYTES, &policies()), None);
    Ok(())
}


#[test]
fn a_kprobe_of_another_policy_is_none() -> TestResult {
    let line = fixture("write-passwd.json")?.replace("ostyr-fim-server", "other-policy");
    assert_eq!(classify(&line, MAX_EVENT_LINE_BYTES, &policies()), None);
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
    assert_eq!(classify(&line, MAX_EVENT_LINE_BYTES, &policies()), None);
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
        .all(|line| classify(line, MAX_EVENT_LINE_BYTES, &policies()).is_none()));
    Ok(())
}


#[test]
fn the_path_comes_from_the_argument_the_hook_names() -> TestResult {
    let permission = kprobe_line(
        "ostyr-fim-a",
        "security_file_permission",
        &json!([{"file_arg": {"path": "/etc/passwd"}}, {"path_arg": {"path": "/etc/shadow"}}]),
        &json!({"binary": "/bin/x"}),
    );
    let rename = kprobe_line(
        "ostyr-fimn-server",
        "security_path_rename",
        &json!([{"path_arg": {"path": "/etc"}}, {"path_arg": {"path": "/etc/passwd"}}]),
        &json!({"binary": "/bin/x"}),
    );
    assert!(matches!(classify(&permission, MAX_EVENT_LINE_BYTES, &policies()), Some(FimEvent::Write { path, .. }) if path == "/etc/passwd"));
    assert!(matches!(classify(&rename, MAX_EVENT_LINE_BYTES, &policies()), Some(FimEvent::Write { path, .. }) if path == "/etc/passwd"));
    Ok(())
}


#[test]
fn a_hook_event_missing_its_argument_is_none() -> TestResult {
    let rename = kprobe_line(
        "ostyr-fimn-server",
        "security_path_rename",
        &json!([{"path_arg": {"path": "/etc"}}]),
        &json!({"binary": "/bin/x"}),
    );
    let link = kprobe_line(
        "ostyr-fimn-server",
        "security_path_link",
        &json!([{"path_arg": {"path": "/etc/passwd"}}]),
        &json!({"binary": "/bin/x"}),
    );
    assert_eq!(classify(&rename, MAX_EVENT_LINE_BYTES, &policies()), None);
    assert_eq!(classify(&link, MAX_EVENT_LINE_BYTES, &policies()), None);
    Ok(())
}


#[test]
fn a_captured_rename_over_passwd_reports_the_file_not_the_directory() -> TestResult {
    assert_eq!(
        classify(&fixture("rename-passwd.json")?, MAX_EVENT_LINE_BYTES, &policies()),
        Some(FimEvent::Write {
            path: "/etc/passwd".to_string(),
            process: "/usr/bin/mv".to_string()
        })
    );
    Ok(())
}


#[test]
fn captured_mapping_symlink_chmod_and_chown_are_writes() -> TestResult {
    let expected = [
        ("mmap-passwd.json", "/etc/passwd"),
        ("symlink-unit.json", "/etc/systemd/system/evil.service"),
        ("chmod-shadow.json", "/etc/shadow"),
        ("chown-shadow.json", "/etc/shadow"),
    ];
    for (name, wanted) in expected {
        assert!(
            matches!(classify(&fixture(name)?, MAX_EVENT_LINE_BYTES, &policies()), Some(FimEvent::Write { path, .. }) if path == wanted),
            "{name}"
        );
    }
    Ok(())
}


#[test]
fn captured_hard_links_report_both_names() -> TestResult {
    assert_eq!(
        classify(&fixture("link-token.json")?, MAX_EVENT_LINE_BYTES, &policies()),
        Some(FimEvent::Link {
            existing: "/root/passwords.txt".to_string(),
            created: "/tmp/hl".to_string(),
            process: "/usr/bin/ln".to_string()
        })
    );
    assert!(matches!(
        classify(&fixture("link-cron.json")?, MAX_EVENT_LINE_BYTES, &policies()),
        Some(FimEvent::Link { created, .. }) if created == "/etc/cron.d/h"
    ));
    Ok(())
}


#[test]
fn a_padded_command_line_does_not_hide_the_honeytoken_open() -> TestResult {
    let line = fixture("padded-open.json")?;
    assert_eq!(line.trim_end().len(), PADDED_BYTES);
    assert!(matches!(
        classify(&line, MAX_EVENT_LINE_BYTES, &policies()),
        Some(FimEvent::Honeytoken { path, process }) if path == "/root/passwords.txt" && process == "/usr/bin/cat"
    ));
    Ok(())
}


#[test]
fn a_padded_write_is_still_a_write() -> TestResult {
    let line = fixture("write-passwd.json")?.replace("-a /etc/passwd", &"A".repeat(PADDED_BYTES));
    assert!(matches!(
        classify(&line, MAX_EVENT_LINE_BYTES, &policies()),
        Some(FimEvent::Write { path, .. }) if path == "/etc/passwd"
    ));
    Ok(())
}


#[test]
fn a_policy_name_is_matched_exactly() -> TestResult {
    let line = fixture("write-passwd.json")?;
    assert!(classify(&line.replace("ostyr-fim-server", "ostyr-fim-evil"), MAX_EVENT_LINE_BYTES, &policies()).is_none());
    assert!(classify(&line, MAX_EVENT_LINE_BYTES, &[]).is_none());
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
        .all(|line| matches!(classify(line, MAX_EVENT_LINE_BYTES, &policies()), Some(FimEvent::Honeytoken { process, .. }) if process == "unknown")));
    Ok(())
}


#[test]
fn a_line_over_the_hard_cap_naming_a_policy_is_an_oversized_event() -> TestResult {
    let line = fixture("write-passwd.json")?.replace("-a /etc/passwd", &"A".repeat(OVER_HARD_CAP));
    assert_eq!(
        classify(&line, MAX_EVENT_LINE_BYTES, &policies()),
        Some(FimEvent::Oversized {
            policy: "ostyr-fim-server".to_string(),
            bytes: line.len()
        })
    );
    let small = fixture("write-passwd.json")?;
    assert_eq!(
        classify(&small, small.len() - 1, &policies()),
        Some(FimEvent::Oversized {
            policy: "ostyr-fim-server".to_string(),
            bytes: small.len()
        })
    );
    assert!(matches!(classify(&small, small.len(), &policies()), Some(FimEvent::Write { .. })));
    Ok(())
}


#[test]
fn an_oversized_line_of_no_policy_of_ours_is_none() -> TestResult {
    let other = write_line("/etc/passwd").replace("ostyr-fim-server", "other");
    let spaced = fixture("write-passwd.json")?.replace("\"policy_name\":", "\"policy_name\": ");
    assert_eq!(classify(&other, SMALL_LINE_CAP, &policies()), None);
    assert_eq!(classify(&spaced, SMALL_LINE_CAP, &policies()), None);
    assert!(classify(&write_line(&"a".repeat(BIG_LINE)), MAX_EVENT_LINE_BYTES, &policies()).is_some());
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
    assert!(lines.iter().all(|line| classify(line, MAX_EVENT_LINE_BYTES, &policies()).is_none()));
    Ok(())
}


#[test]
fn control_characters_are_escaped_in_the_path() -> TestResult {
    let line = write_line("/etc/x \u{1b}[31m\n\u{202e}é\\");
    assert!(matches!(
        classify(&line, MAX_EVENT_LINE_BYTES, &policies()),
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
