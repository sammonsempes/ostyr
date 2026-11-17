use crate::support::{fixture, sets};
use crate::types::TestResult;
use linux_fim::classify::classify;
use linux_fim::limits::{MAX_EVENT_LINE_BYTES, MAX_KPROBE_ARGS};
use linux_fim::model::FimEvent;
use linux_fim::policy::policy_names;
use serde_json::json;


fn policies() -> Vec<String> {
    policy_names("server")
}


fn kprobe_line(policy: &str, function: &str, args: &serde_json::Value, process: &serde_json::Value) -> String {
    json!({"process_kprobe": {"policy_name": policy, "function_name": function, "args": args, "process": process}}).to_string()
}


fn named_event(name: &str) -> Result<Option<FimEvent>, Box<dyn std::error::Error>> {
    Ok(classify(&fixture(name)?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?))
}


#[test]
fn captured_removals_and_attribute_changes_are_writes() -> TestResult {
    let expected = [
        ("unlink-cron.json", "/etc/cron.d/t465job"),
        ("setcap-bin.json", "/usr/bin/t465true"),
        ("acl-shadow.json", "/etc/shadow"),
        ("mprotect-map.json", "/etc/passwd"),
    ];
    for (name, wanted) in expected {
        assert!(
            matches!(named_event(name)?, Some(FimEvent::Write { path, .. }) if path == wanted),
            "{name}"
        );
    }
    Ok(())
}


#[test]
fn captured_renames_of_directories_and_honeytokens_name_both_sides() -> TestResult {
    assert!(matches!(
        named_event("rename-dir-ssh.json")?,
        Some(FimEvent::Rename { source, honeytoken: false, .. }) if source == "/root/.ssh"
    ));
    assert!(matches!(
        named_event("rename-token.json")?,
        Some(FimEvent::Rename { source, target, honeytoken: true, .. }) if source == "/root/passwords.txt" && target == "/root/p2"
    ));
    assert!(matches!(
        named_event("exchange-passwd.json")?,
        Some(FimEvent::Rename { source, honeytoken: false, .. }) if source == "/etc/passwd"
    ));
    Ok(())
}


#[test]
fn removals_in_the_honeytoken_policy_are_honeytoken_events() -> TestResult {
    let args = json!([{"path_arg": {"path": "/root/.aws"}}, {"path_arg": {"path": "/credentials"}}]);
    let unlink = kprobe_line("ostyr-fimt-server", "security_path_unlink", &args, &json!({"binary": "/usr/bin/rm"}));
    let rmdir_args = json!([{"path_arg": {"path": "/root"}}, {"path_arg": {"path": "/.aws"}}]);
    let rmdir = kprobe_line("ostyr-fimt-server", "security_path_rmdir", &rmdir_args, &json!({"binary": "/usr/bin/rm"}));
    let watched = unlink.replace("ostyr-fimt-server", "ostyr-fimd-server");
    assert!(
        matches!(classify(&unlink, MAX_EVENT_LINE_BYTES, &policies(), &sets()?), Some(FimEvent::Honeytoken { path, .. }) if path == "/root/.aws/credentials")
    );
    assert!(matches!(classify(&rmdir, MAX_EVENT_LINE_BYTES, &policies(), &sets()?), Some(FimEvent::Honeytoken { path, .. }) if path == "/root/.aws"));
    assert!(matches!(
        classify(&watched, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Write { .. })
    ));
    Ok(())
}


#[test]
fn a_line_with_too_many_arguments_is_oversized_never_dropped() -> TestResult {
    let many: Vec<serde_json::Value> = (0..=MAX_KPROBE_ARGS).map(|_| json!({"int_arg": 1})).collect();
    let line = kprobe_line("ostyr-fim-server", "security_file_permission", &json!(many), &json!({"binary": "/bin/x"}));
    assert_eq!(
        classify(&line, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Oversized {
            policy: "ostyr-fim-server".to_string(),
            bytes: line.len()
        })
    );
    let other = line.replace("ostyr-fim-server", "other");
    assert_eq!(classify(&other, MAX_EVENT_LINE_BYTES, &policies(), &sets()?), None);
    Ok(())
}


#[test]
fn the_oversized_match_needs_the_compact_form_tetragon_writes() -> TestResult {
    let line = kprobe_line("ostyr-fim-server", "security_file_permission", &json!([]), &json!({}));
    assert!(line.contains("\"policy_name\":\"ostyr-fim-server\""));
    let forged = line.replace("\"policy_name\":", "\"policy_name\": ");
    assert_eq!(classify(&forged, line.len() - 1, &policies(), &sets()?), None);
    Ok(())
}


#[test]
fn captured_deep_source_events_matched_on_the_target_are_reported() -> TestResult {
    assert!(matches!(
        named_event("deep15-rename-passwd.json")?,
        Some(FimEvent::Rename { source, target, honeytoken: false, .. }) if source.contains("[cut ") && target == "/etc/passwd"
    ));
    assert!(matches!(
        named_event("deep15-link-preload.json")?,
        Some(FimEvent::Link { existing, created, honeytoken: false, .. }) if existing.contains("[cut ") && created == "/etc/ld.so.preload"
    ));
    assert!(matches!(
        named_event("deep15-token-rename.json")?,
        Some(FimEvent::Rename { source, target, honeytoken: true, .. }) if source.contains("[cut ") && target == "/root/passwords.txt"
    ));
    assert!(matches!(
        named_event("deep15-token-dir-rename.json")?,
        Some(FimEvent::Rename { source, target, honeytoken: true, .. }) if source.contains("[cut ") && target == "/root/.aws"
    ));
    assert!(matches!(
        named_event("deep15-ancestor-rename.json")?,
        Some(FimEvent::Rename { source, target, honeytoken: false, .. }) if source.contains("[cut ") && target == "/root/.ssh"
    ));
    Ok(())
}
