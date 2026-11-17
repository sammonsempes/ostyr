use crate::support::{fixture, sets, MAY_WRITE, SMALL_CAP};
use crate::types::TestResult;
use linux_fim::classify::{classify, escape_field};
use linux_fim::limits::{MAX_EVENT_LINE_BYTES, MAX_FIELD_BYTES, UNRESOLVED_NAME};
use linux_fim::model::FimEvent;
use linux_fim::policy::policy_names;
use serde_json::json;


const BIG_LINE: usize = 65_536;


const PADDED_BYTES: usize = 201_075;


const SMALL_LINE_CAP: usize = 10;


const OVER_HARD_CAP: usize = 5_000_000;


fn policies() -> Vec<String> {
    policy_names("server").into_iter().chain(policy_names("a")).collect()
}


const OVER_FIELD: usize = 2000;


const THIRD_INDEX: usize = 2;


fn token_arg() -> serde_json::Value {
    json!({"file_arg": {"path": "/root/passwords.txt"}})
}


fn kprobe_line(policy: &str, function: &str, args: &serde_json::Value, process: &serde_json::Value) -> String {
    json!({"process_kprobe": {"policy_name": policy, "function_name": function, "args": args, "process": process}}).to_string()
}


fn write_line(path: &str) -> String {
    kprobe_line(
        "ostyr-fim-server",
        "security_file_permission",
        &json!([{"file_arg": {"path": path}}, {"int_arg": MAY_WRITE}]),
        &json!({"binary": "/usr/bin/tee", "process_credentials": {"euid": 0}}),
    )
}


#[test]
fn a_captured_write_to_passwd_is_a_write() -> TestResult {
    assert_eq!(
        classify(&fixture("write-passwd.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Write {
            path: "/etc/passwd".to_string(),
            process: "/usr/bin/tee".to_string(),
            name_match: false,
            foreign_mount_ns: false,
            mount_ambiguous: false,
            dentry_path: None,
        })
    );
    Ok(())
}


#[test]
fn a_captured_write_to_a_unit_is_a_write() -> TestResult {
    assert!(matches!(
        classify(&fixture("write-unit.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Write { path, .. }) if path == "/etc/systemd/system/x.service"
    ));
    Ok(())
}


#[test]
fn a_captured_creation_reports_the_directory() -> TestResult {
    assert!(matches!(
        classify(&fixture("create-cron.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Write { path, process, .. }) if path == "/etc/cron.d" && process == "/usr/bin/touch"
    ));
    Ok(())
}


#[test]
fn a_captured_open_of_a_canary_is_a_honeytoken_event() -> TestResult {
    assert_eq!(
        classify(&fixture("open-canary.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Honeytoken {
            path: "/var/backups/.canary".to_string(),
            process: "/usr/bin/cat".to_string()
        })
    );
    Ok(())
}


#[test]
fn an_unrelated_event_is_none() -> TestResult {
    assert_eq!(
        classify(&fixture("process-exec.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        None
    );
    Ok(())
}


#[test]
fn a_kprobe_of_another_policy_is_none() -> TestResult {
    let line = fixture("write-passwd.json")?.replace("ostyr-fim-server", "other-policy");
    assert_eq!(classify(&line, MAX_EVENT_LINE_BYTES, &policies(), &sets()?), None);
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
    assert_eq!(classify(&line, MAX_EVENT_LINE_BYTES, &policies(), &sets()?), None);
    Ok(())
}


#[test]
fn a_kprobe_without_policy_or_function_is_none() -> TestResult {
    let no_policy = json!({"process_kprobe": {"function_name": "security_file_open", "args": [{"file_arg": {"path": "/a"}}]}}).to_string();
    let no_function = json!({"process_kprobe": {"policy_name": "ostyr-fim-a", "args": [{"file_arg": {"path": "/a"}}]}}).to_string();
    let declared = sets()?;
    assert!([no_policy, no_function]
        .iter()
        .all(|line| classify(line, MAX_EVENT_LINE_BYTES, &policies(), &declared).is_none()));
    Ok(())
}


#[test]
fn a_content_or_removal_event_without_a_path_is_reported_as_missing_never_dropped() -> TestResult {
    let no_args = json!({"process_kprobe": {"policy_name": "ostyr-fim-a", "function_name": "security_file_open"}}).to_string();
    let no_path = kprobe_line(
        "ostyr-fim-a",
        "security_file_open",
        &json!([{"int_arg": 1}, {"file_arg": {}}]),
        &json!({}),
    );
    let write = kprobe_line(
        "ostyr-fim-a",
        "security_file_permission",
        &json!([{"file_arg": {}}]),
        &json!({"binary": "/bin/x", "process_credentials": {"euid": 0}}),
    );
    let removal = kprobe_line("ostyr-fimt-a", "security_path_unlink", &json!([{"path_arg": {}}]), &json!({}));
    let expected = |policy: &str, function: &str, process: &str| FimEvent::MissingPath {
        policy: policy.to_string(),
        function: function.to_string(),
        process: process.to_string(),
    };
    assert_eq!(
        classify(&no_args, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(expected("ostyr-fim-a", "security_file_open", "unknown"))
    );
    assert_eq!(
        classify(&no_path, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(expected("ostyr-fim-a", "security_file_open", "unknown"))
    );
    assert_eq!(
        classify(&write, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(expected("ostyr-fim-a", "security_file_permission", "/bin/x"))
    );
    assert_eq!(
        classify(&removal, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(expected("ostyr-fimt-a", "security_path_unlink", "unknown"))
    );
    Ok(())
}


fn named(path: &str) -> serde_json::Value {
    json!({"path_arg": {"path": path}})
}


fn unresolved() -> serde_json::Value {
    json!({"path_arg": {"flags": "unresolvedPathComponents"}})
}


#[test]
fn a_target_first_event_is_read_back_in_source_target_order() -> TestResult {
    let rename_args = json!([named("/etc"), named("/passwd"), unresolved()]);
    let link_args = json!([named("/etc"), named("/passwd"), unresolved()]);
    let rename = kprobe_line(
        "ostyr-fimr-server",
        "security_path_rename",
        &rename_args,
        &json!({"binary": "/bin/mv", "process_credentials": {"euid": 0}}),
    );
    let link = kprobe_line(
        "ostyr-fimr-server",
        "security_path_link",
        &link_args,
        &json!({"binary": "/bin/ln", "process_credentials": {"euid": 0}}),
    );
    let ancestor = kprobe_line(
        "ostyr-fimb-server",
        "security_path_rename",
        &rename_args,
        &json!({"binary": "/bin/mv", "process_credentials": {"euid": 0}}),
    );
    assert!(matches!(
        classify(&rename, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Rename { source, target, honeytoken: false, .. }) if source == UNRESOLVED_NAME && target == "/etc/passwd"
    ));
    assert!(matches!(
        classify(&ancestor, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Rename { source, target, honeytoken: false, .. }) if source == UNRESOLVED_NAME && target == "/etc/passwd"
    ));
    assert!(matches!(
        classify(&link, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Link { existing, created, honeytoken: false, name_match: false, .. }) if existing == UNRESOLVED_NAME && created == "/etc/passwd"
    ));
    Ok(())
}


#[test]
fn a_target_first_honeytoken_event_keeps_its_severity() -> TestResult {
    let rename_args = json!([named("/root"), named("/passwords.txt"), named("/tmp"), named("/x")]);
    let link_args = json!([named("/root"), named("/passwords.txt"), named("/x")]);
    let rename = kprobe_line(
        "ostyr-fimu-server",
        "security_path_rename",
        &rename_args,
        &json!({"binary": "/bin/mv", "process_credentials": {"euid": 0}}),
    );
    let link = kprobe_line(
        "ostyr-fimu-server",
        "security_path_link",
        &link_args,
        &json!({"binary": "/bin/ln", "process_credentials": {"euid": 0}}),
    );
    assert!(matches!(
        classify(&rename, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Rename { source, target, honeytoken: true, .. }) if source == "/tmp/x" && target == "/root/passwords.txt"
    ));
    assert!(matches!(
        classify(&link, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Link { existing, created, honeytoken: true, name_match: false, .. }) if existing == "/x" && created == "/root/passwords.txt"
    ));
    Ok(())
}


#[test]
fn a_source_first_link_matched_on_the_existing_name_alone_is_a_name_match() -> TestResult {
    let args = json!([named("/etc/passwd"), named("/tmp"), named("/hl")]);
    let link = kprobe_line(
        "ostyr-fimn-server",
        "security_path_link",
        &args,
        &json!({"binary": "/bin/ln", "process_credentials": {"euid": 0}}),
    );
    assert_eq!(
        classify(&link, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Link {
            existing: "/etc/passwd".to_string(),
            created: "/tmp/hl".to_string(),
            process: "/bin/ln".to_string(),
            honeytoken: false,
            name_match: true,
            foreign_mount_ns: false,
            mount_ambiguous: false,
            created_dentry: None,
        })
    );
    Ok(())
}


#[test]
fn a_directory_and_a_dentry_from_a_mount_root_join_to_the_declared_path() -> TestResult {
    let tmpfs = json!([named("/var/backups"), named("/.canary")]);
    let root_fs = json!([named("/var/backups"), named("/var/backups/.canary")]);
    let at_root = json!([named("/"), named("/etc")]);
    let empty_name = json!([named("/etc"), named("/")]);
    let line = |args: &serde_json::Value| {
        kprobe_line(
            "ostyr-fimt-server",
            "security_path_unlink",
            args,
            &json!({"binary": "/bin/rm", "process_credentials": {"euid": 0}}),
        )
    };
    let declared = sets()?;
    let paths: Vec<Option<FimEvent>> = [&tmpfs, &root_fs, &at_root]
        .iter()
        .map(|args| classify(&line(args), MAX_EVENT_LINE_BYTES, &policies(), &declared))
        .collect();
    assert!(matches!(paths.first(), Some(Some(FimEvent::Honeytoken { path, .. })) if path == "/var/backups/.canary"));
    assert!(matches!(paths.get(1), Some(Some(FimEvent::Honeytoken { path, .. })) if path == "/var/backups/.canary"));
    assert!(matches!(paths.get(THIRD_INDEX), Some(Some(FimEvent::Write { path, name_match: true, .. })) if path == "/etc"));
    assert!(matches!(
        classify(&line(&empty_name), MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::MissingPath { .. })
    ));
    Ok(())
}


#[test]
fn a_dentry_only_hook_is_a_name_match_and_a_path_hook_is_not() -> TestResult {
    let setxattr = kprobe_line(
        "ostyr-fimx-server",
        "security_inode_setxattr",
        &json!([named("/passwd")]),
        &json!({"binary": "/bin/x", "process_credentials": {"euid": 0}}),
    );
    let chmod = kprobe_line(
        "ostyr-fimd-server",
        "security_path_chmod",
        &json!([named("/etc/shadow")]),
        &json!({"binary": "/bin/x", "process_credentials": {"euid": 0}}),
    );
    let unlink = kprobe_line(
        "ostyr-fimd-server",
        "security_path_unlink",
        &json!([named("/etc/cron.d"), named("/x")]),
        &json!({"binary": "/bin/x", "process_credentials": {"euid": 0}}),
    );
    assert!(matches!(
        classify(&setxattr, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Write { path, name_match: true, .. }) if path == "/passwd"
    ));
    assert!(matches!(
        classify(&chmod, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Write { name_match: false, .. })
    ));
    assert!(matches!(
        classify(&unlink, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Write { path, name_match: false, .. }) if path == "/etc/cron.d/x"
    ));
    Ok(())
}


#[test]
fn the_path_comes_from_the_argument_the_hook_names() -> TestResult {
    let permission = kprobe_line(
        "ostyr-fim-a",
        "security_file_permission",
        &json!([{"file_arg": {"path": "/etc/passwd"}}, {"path_arg": {"path": "/etc/shadow"}}]),
        &json!({"binary": "/bin/x", "process_credentials": {"euid": 0}}),
    );
    let rename = kprobe_line(
        "ostyr-fimn-server",
        "security_path_rename",
        &json!([named("/root"), named("/p"), named("/etc"), named("/passwd")]),
        &json!({"binary": "/bin/x", "process_credentials": {"euid": 0}}),
    );
    assert!(
        matches!(classify(&permission, MAX_EVENT_LINE_BYTES, &policies(), &sets()?), Some(FimEvent::Write { path, .. }) if path == "/etc/passwd")
    );
    assert_eq!(
        classify(&rename, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Rename {
            source: "/root/p".to_string(),
            target: "/etc/passwd".to_string(),
            process: "/bin/x".to_string(),
            honeytoken: false,
            foreign_mount_ns: false,
            mount_ambiguous: false,
            source_dentry: None,
            target_dentry: None,
        })
    );
    Ok(())
}


#[test]
fn a_hook_event_missing_its_argument_keeps_the_unresolved_marker() -> TestResult {
    let rename = kprobe_line(
        "ostyr-fimn-server",
        "security_path_rename",
        &json!([named("/etc"), named("/passwd")]),
        &json!({"binary": "/bin/x", "process_credentials": {"euid": 0}}),
    );
    let link = kprobe_line(
        "ostyr-fimn-server",
        "security_path_link",
        &json!([named("/etc/passwd")]),
        &json!({"binary": "/bin/x", "process_credentials": {"euid": 0}}),
    );
    assert!(matches!(
        classify(&rename, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Rename { source, target, .. }) if source == "/etc/passwd" && target == UNRESOLVED_NAME
    ));
    assert!(matches!(
        classify(&link, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Link { existing, created, .. }) if existing == "/etc/passwd" && created == UNRESOLVED_NAME
    ));
    Ok(())
}


#[test]
fn captured_deep_chain_events_are_reported_with_the_unresolved_marker() -> TestResult {
    assert!(matches!(
        classify(&fixture("deep-link.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Link { existing, created, honeytoken: false, .. }) if existing == UNRESOLVED_NAME && created == "/etc/cron.d/t465plantln30"
    ));
    assert!(matches!(
        classify(&fixture("deep-rename.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Rename { source, target, honeytoken: false, .. }) if source == UNRESOLVED_NAME && target == "/etc/cron.d/t465plantmv30"
    ));
    Ok(())
}


#[test]
fn captured_deep_chain_moves_and_token_links_are_never_dropped() -> TestResult {
    assert!(matches!(
        classify(&fixture("deep-rename-away.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Rename { source, target, .. }) if source == "/etc/cron.d/t465deep" && target == UNRESOLVED_NAME
    ));
    assert!(matches!(
        classify(&fixture("deep-token-link.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Link { existing, created, honeytoken: true, .. }) if existing == "/root/passwords.txt" && created == UNRESOLVED_NAME
    ));
    Ok(())
}


#[test]
fn a_captured_symlink_at_a_missing_ancestor_is_a_write() -> TestResult {
    assert!(matches!(
        classify(&fixture("symlink-missing-ssh.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Write { path, .. }) if path == "/root/.ssh"
    ));
    Ok(())
}


#[test]
fn an_unresolved_name_in_a_honeytoken_policy_keeps_its_severity() -> TestResult {
    let args = json!([{"path_arg": {"flags": "unresolvedPathComponents"}}, {"path_arg": {"path": "/tmp/deep/x"}}]);
    let rename = kprobe_line(
        "ostyr-fimt-server",
        "security_path_rename",
        &args,
        &json!({"binary": "/bin/mv", "process_credentials": {"euid": 0}}),
    );
    let link = kprobe_line(
        "ostyr-fimt-server",
        "security_path_link",
        &args,
        &json!({"binary": "/bin/ln", "process_credentials": {"euid": 0}}),
    );
    assert!(matches!(
        classify(&rename, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Rename { honeytoken: true, .. })
    ));
    assert!(matches!(
        classify(&link, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Link { honeytoken: true, .. })
    ));
    Ok(())
}


#[test]
fn a_captured_rename_over_passwd_reports_both_names() -> TestResult {
    assert_eq!(
        classify(&fixture("rename-passwd.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Rename {
            source: "/root/p.new".to_string(),
            target: "/etc/passwd".to_string(),
            process: "/usr/bin/mv".to_string(),
            honeytoken: false,
            foreign_mount_ns: false,
            mount_ambiguous: false,
            source_dentry: None,
            target_dentry: None,
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
            matches!(classify(&fixture(name)?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?), Some(FimEvent::Write { path, .. }) if path == wanted),
            "{name}"
        );
    }
    Ok(())
}


#[test]
fn captured_hard_links_report_both_names() -> TestResult {
    assert_eq!(
        classify(&fixture("link-token.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Link {
            existing: "/root/passwords.txt".to_string(),
            created: "/tmp/hl".to_string(),
            process: "/usr/bin/ln".to_string(),
            honeytoken: false,
            name_match: true,
            foreign_mount_ns: false,
            mount_ambiguous: false,
            created_dentry: None,
        })
    );
    assert!(matches!(
        classify(&fixture("link-cron.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Link { created, .. }) if created == "/etc/cron.d/hl"
    ));
    Ok(())
}


#[test]
fn a_padded_command_line_does_not_hide_the_honeytoken_open() -> TestResult {
    let line = fixture("padded-open.json")?;
    assert_eq!(line.trim_end().len(), PADDED_BYTES);
    assert!(matches!(
        classify(&line, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Honeytoken { path, process }) if path == "/root/passwords.txt" && process == "/usr/bin/cat"
    ));
    Ok(())
}


#[test]
fn a_padded_write_is_still_a_write() -> TestResult {
    let line = fixture("write-passwd.json")?.replace("-a /etc/passwd", &"A".repeat(PADDED_BYTES));
    assert!(matches!(
        classify(&line, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Write { path, .. }) if path == "/etc/passwd"
    ));
    Ok(())
}


#[test]
fn a_policy_name_is_matched_exactly() -> TestResult {
    let line = fixture("write-passwd.json")?;
    assert!(classify(
        &line.replace("ostyr-fim-server", "ostyr-fim-evil"),
        MAX_EVENT_LINE_BYTES,
        &policies(),
        &sets()?
    )
    .is_none());
    assert!(classify(&line, MAX_EVENT_LINE_BYTES, &[], &sets()?).is_none());
    Ok(())
}


#[test]
fn a_missing_process_is_unknown_not_dropped() -> TestResult {
    let no_process =
        json!({"process_kprobe": {"policy_name": "ostyr-fim-a", "function_name": "security_file_open", "args": [token_arg()]}}).to_string();
    let no_binary = kprobe_line(
        "ostyr-fim-a",
        "security_file_open",
        &json!([token_arg()]),
        &json!({"pid": 1, "process_credentials": {"euid": 0}}),
    );
    let declared = sets()?;
    assert!(matches!(
        classify(&no_binary, MAX_EVENT_LINE_BYTES, &policies(), &declared),
        Some(FimEvent::Honeytoken { process, .. }) if process == "unknown"
    ));
    assert!(matches!(
        classify(&no_process, MAX_EVENT_LINE_BYTES, &policies(), &declared),
        Some(FimEvent::Write { process, mount_ambiguous: true, .. }) if process == "unknown"
    ));
    Ok(())
}


#[test]
fn a_line_over_the_hard_cap_naming_a_policy_is_an_oversized_event() -> TestResult {
    let line = fixture("write-passwd.json")?.replace("-a /etc/passwd", &"A".repeat(OVER_HARD_CAP));
    assert_eq!(
        classify(&line, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Oversized {
            policy: "ostyr-fim-server".to_string(),
            bytes: line.len()
        })
    );
    let small = fixture("write-passwd.json")?;
    assert_eq!(
        classify(&small, small.len() - 1, &policies(), &sets()?),
        Some(FimEvent::Oversized {
            policy: "ostyr-fim-server".to_string(),
            bytes: small.len()
        })
    );
    assert!(matches!(
        classify(&small, small.len(), &policies(), &sets()?),
        Some(FimEvent::Write { .. })
    ));
    Ok(())
}


#[test]
fn an_oversized_line_of_no_policy_of_ours_is_none() -> TestResult {
    let other = write_line("/etc/passwd").replace("ostyr-fim-server", "other");
    let spaced = fixture("write-passwd.json")?.replace("\"policy_name\":", "\"policy_name\": ");
    assert_eq!(classify(&other, SMALL_LINE_CAP, &policies(), &sets()?), None);
    assert_eq!(classify(&spaced, SMALL_LINE_CAP, &policies(), &sets()?), None);
    assert!(classify(&write_line(&"a".repeat(BIG_LINE)), MAX_EVENT_LINE_BYTES, &policies(), &sets()?).is_some());
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
    let declared = sets()?;
    assert!(lines
        .iter()
        .all(|line| classify(line, MAX_EVENT_LINE_BYTES, &policies(), &declared).is_none()));
    Ok(())
}


#[test]
fn control_characters_are_escaped_in_the_path() -> TestResult {
    let line = write_line("/etc/x \u{1b}[31m\n\u{202e}é\\");
    assert!(matches!(
        classify(&line, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
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


#[test]
fn captured_removals_join_the_directory_path_and_the_name() -> TestResult {
    assert!(matches!(
        classify(&fixture("unlink-token.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Honeytoken { path, .. }) if path == "/root/passwords.txt"
    ));
    assert!(matches!(
        classify(&fixture("rmdir-token-dir.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Honeytoken { path, .. }) if path == "/root/.aws"
    ));
    assert!(matches!(
        classify(&fixture("link-source-watched.json")?, MAX_EVENT_LINE_BYTES, &policies(), &sets()?),
        Some(FimEvent::Link { existing, created, name_match: true, honeytoken: false, .. }) if existing == "/etc/passwd" && created == "/root/hlp"
    ));
    Ok(())
}


fn classified(policy: &str, function: &str, args: &serde_json::Value) -> Result<Option<FimEvent>, Box<dyn std::error::Error>> {
    let line = kprobe_line(policy, function, args, &json!({"binary": "/bin/mv", "process_credentials": {"euid": 0}}));
    Ok(classify(&line, MAX_EVENT_LINE_BYTES, &policies(), &sets()?))
}


fn rename_of(source: &str, target: &str, honeytoken: bool) -> Option<FimEvent> {
    Some(FimEvent::Rename {
        source: source.to_string(),
        target: target.to_string(),
        process: "/bin/mv".to_string(),
        honeytoken,
        foreign_mount_ns: false,
        mount_ambiguous: false,
        source_dentry: None,
        target_dentry: None,
    })
}


fn write_of(path: &str, name_match: bool) -> Option<FimEvent> {
    Some(FimEvent::Write {
        path: path.to_string(),
        process: "/bin/mv".to_string(),
        name_match,
        foreign_mount_ns: false,
        mount_ambiguous: false,
        dentry_path: None,
    })
}


fn ambiguous_write(path: &str, dentry: &str) -> Option<FimEvent> {
    Some(FimEvent::Write {
        path: path.to_string(),
        process: "/bin/mv".to_string(),
        name_match: false,
        foreign_mount_ns: false,
        mount_ambiguous: true,
        dentry_path: Some(dentry.to_string()),
    })
}


fn ambiguous_rename(sides: (&str, &str), dentries: (Option<&str>, Option<&str>)) -> Option<FimEvent> {
    Some(FimEvent::Rename {
        source: sides.0.to_string(),
        target: sides.1.to_string(),
        process: "/bin/mv".to_string(),
        honeytoken: false,
        foreign_mount_ns: false,
        mount_ambiguous: true,
        source_dentry: dentries.0.map(str::to_string),
        target_dentry: dentries.1.map(str::to_string),
    })
}


#[test]
fn a_rename_inside_a_bind_mount_of_a_watched_directory_carries_both_paths() -> TestResult {
    let source_first = json!([
        named("/etc/cron.d/stage"),
        named("/mnt/x"),
        named("/etc/cron.d/t465bind"),
        named("/mnt/x")
    ]);
    let target_first = json!([
        named("/etc/cron.d/t465bind"),
        named("/mnt/x"),
        named("/etc/cron.d/stage"),
        named("/mnt/x")
    ]);
    let expected = ambiguous_rename(
        ("/mnt/x/stage", "/mnt/x/t465bind"),
        (Some("/etc/cron.d/stage"), Some("/etc/cron.d/t465bind")),
    );
    assert_eq!(classified("ostyr-fimp-server", "security_path_rename", &source_first)?, expected);
    assert_eq!(classified("ostyr-fimq-server", "security_path_rename", &target_first)?, expected);
    Ok(())
}


#[test]
fn removals_and_new_names_through_a_bind_mount_carry_both_paths() -> TestResult {
    let unlink = json!([named("/etc/cron.d/t465bind"), named("/mnt/x")]);
    let expected = ambiguous_write("/mnt/x/t465bind", "/etc/cron.d/t465bind");
    assert_eq!(classified("ostyr-fimp-server", "security_path_unlink", &unlink)?, expected);
    assert_eq!(classified("ostyr-fimq-server", "security_path_rmdir", &unlink)?, expected);
    assert_eq!(classified("ostyr-fimv-server", "security_path_symlink", &unlink)?, expected);
    let no_directory = json!([named("/etc/passwd"), {"path_arg": {}}]);
    assert!(matches!(
        classified("ostyr-fimp-server", "security_path_unlink", &no_directory)?,
        Some(FimEvent::MissingPath { .. })
    ));
    Ok(())
}


#[test]
fn honeytokens_through_a_bind_mount_of_the_root_are_flagged_and_never_honeytoken_severity() -> TestResult {
    let unlink = json!([named("/root/passwords.txt"), named("/mnt/r/root")]);
    let rmdir = json!([named("/root/.aws"), named("/mnt/r/root")]);
    let moved = json!([
        named("/root/passwords.txt"),
        named("/mnt/r/root"),
        named("/root/stolen.txt"),
        named("/mnt/r/root")
    ]);
    let link = json!([named("/root/s6hl"), named("/mnt/r/root"), named("/root/passwords.txt")]);
    assert_eq!(
        classified("ostyr-fimp-server", "security_path_unlink", &unlink)?,
        ambiguous_write("/mnt/r/root/passwords.txt", "/root/passwords.txt")
    );
    assert_eq!(
        classified("ostyr-fimq-server", "security_path_rmdir", &rmdir)?,
        ambiguous_write("/mnt/r/root/.aws", "/root/.aws")
    );
    assert_eq!(
        classified("ostyr-fimp-server", "security_path_rename", &moved)?,
        ambiguous_rename(
            ("/mnt/r/root/passwords.txt", "/mnt/r/root/stolen.txt"),
            (Some("/root/passwords.txt"), None)
        )
    );
    assert_eq!(
        classified("ostyr-fimv-server", "security_path_link", &link)?,
        Some(FimEvent::Link {
            existing: "/root/passwords.txt".to_string(),
            created: "/mnt/r/root/s6hl".to_string(),
            process: "/bin/mv".to_string(),
            honeytoken: false,
            name_match: false,
            foreign_mount_ns: false,
            mount_ambiguous: false,
            created_dentry: None,
        })
    );
    Ok(())
}


#[test]
fn a_full_path_policy_does_not_trust_an_unresolved_side_for_severity() -> TestResult {
    let args = json!([named("/etc/cron.d/x"), named("/mnt/x"), unresolved(), unresolved()]);
    assert_eq!(
        classified("ostyr-fimp-server", "security_path_rename", &args)?,
        ambiguous_rename(("/mnt/x/x", UNRESOLVED_NAME), (Some("/etc/cron.d/x"), None))
    );
    Ok(())
}


#[test]
fn the_directory_times_name_product_does_not_give_an_unrelated_file_honeytoken_severity() -> TestResult {
    let moved = json!([named("/root"), named("/root/credentials"), named("/root"), named("/root/other")]);
    assert_eq!(
        classified("ostyr-fimt-server", "security_path_rename", &moved)?,
        rename_of("/root/credentials", "/root/other", false)
    );
    let unlink = json!([named("/root"), named("/credentials")]);
    assert_eq!(
        classified("ostyr-fimt-server", "security_path_unlink", &unlink)?,
        write_of("/root/credentials", true)
    );
    let declared = json!([
        named("/root/.aws"),
        named("/root/.aws/credentials"),
        named("/root/.aws"),
        named("/root/.aws/moved")
    ]);
    assert_eq!(
        classified("ostyr-fimt-server", "security_path_rename", &declared)?,
        rename_of("/root/.aws/credentials", "/root/.aws/moved", true)
    );
    Ok(())
}


#[test]
fn a_link_source_known_by_its_dentry_alone_is_never_a_honeytoken() -> TestResult {
    let link = |existing: &str| json!([named(existing), named("/tmp"), named("/hl")]);
    let honeytoken_of = |event: Option<FimEvent>| matches!(event, Some(FimEvent::Link { honeytoken: true, .. }));
    assert!(!honeytoken_of(classified("ostyr-fimt-server", "security_path_link", &link("/.canary"))?));
    assert!(!honeytoken_of(classified(
        "ostyr-fimt-server",
        "security_path_link",
        &link("/root/passwords.txt")
    )?));
    assert!(!honeytoken_of(classified("ostyr-fimt-server", "security_path_link", &link("/"))?));
    Ok(())
}


#[test]
fn captured_bind_mount_events_are_flagged_with_both_paths() -> TestResult {
    let declared = sets()?;
    let classify_fixture = |name: &str| -> Result<Option<FimEvent>, Box<dyn std::error::Error>> {
        Ok(classify(&fixture(name)?, MAX_EVENT_LINE_BYTES, &policies(), &declared))
    };
    let process = |event: Option<FimEvent>| match event {
        Some(FimEvent::Rename {
            source,
            target,
            honeytoken,
            mount_ambiguous,
            ..
        }) => (source, target, honeytoken, mount_ambiguous),
        _ => (String::new(), String::new(), false, false),
    };
    let flagged = |source: &str, target: &str| (source.to_string(), target.to_string(), false, true);
    assert_eq!(
        process(classify_fixture("bind-rename-cron.json")?),
        flagged("/mnt/x/stage", "/mnt/x/t465bind")
    );
    assert_eq!(
        process(classify_fixture("bind-rename-cron-target.json")?),
        flagged("/mnt/x/stage", "/mnt/x/t465bind")
    );
    assert_eq!(
        process(classify_fixture("bind-rename-passwd.json")?),
        flagged("/mnt/r/etc/s6p", "/mnt/r/etc/passwd")
    );
    assert_eq!(
        process(classify_fixture("bind-rename-token.json")?),
        flagged("/mnt/r/root/passwords.txt", "/mnt/r/root/stolen.txt")
    );
    assert_eq!(
        process(classify_fixture("bind-rename-token-back.json")?),
        flagged("/mnt/r/root/stolen.txt", "/mnt/r/root/passwords.txt")
    );
    assert!(matches!(
        classify_fixture("bind-unlink-cron.json")?,
        Some(FimEvent::Write { path, name_match: false, mount_ambiguous: true, .. }) if path == "/mnt/x/t465bind"
    ));
    Ok(())
}


#[test]
fn a_bind_mount_of_the_root_is_an_exact_match_when_the_joined_path_equals_the_dentry() -> TestResult {
    let unlink = json!([named("/root/passwords.txt"), named("/root")]);
    assert_eq!(
        classified("ostyr-fimp-server", "security_path_unlink", &unlink)?,
        Some(FimEvent::Honeytoken {
            path: "/root/passwords.txt".to_string(),
            process: "/bin/mv".to_string()
        })
    );
    Ok(())
}


const SPOOF_COUNT: usize = 8;


const BIND_COUNT: usize = 11;


const BIND_FULL_COUNT: usize = 6;


const FULL_POLICIES: [&str; 3] = ["ostyr-fimp-", "ostyr-fimq-", "ostyr-fimv-"];


const SPOOF_LINES: &str = include_str!("../fixtures/spoof-lines.jsonl");


const BIND_LINES: &str = include_str!("../fixtures/bind-lines.jsonl");


#[test]
fn every_captured_spoof_line_is_flagged_with_its_real_path_and_never_a_honeytoken() -> TestResult {
    let declared = sets()?;
    let events: Vec<Option<FimEvent>> = SPOOF_LINES
        .lines()
        .map(|line| classify(line, MAX_EVENT_LINE_BYTES, &policies(), &declared))
        .collect();
    assert_eq!(events.len(), SPOOF_COUNT);
    assert!(events.iter().all(|event| match event {
        Some(FimEvent::Write {
            path,
            foreign_mount_ns: false,
            mount_ambiguous: true,
            dentry_path: Some(_),
            ..
        }) => path.starts_with("/dev/shm/"),
        Some(FimEvent::Rename {
            source,
            target,
            honeytoken: false,
            foreign_mount_ns: false,
            mount_ambiguous: true,
            ..
        }) => source.starts_with("/dev/shm/") || target.starts_with("/dev/shm/"),
        Some(FimEvent::Link {
            created,
            honeytoken: false,
            foreign_mount_ns: false,
            mount_ambiguous: true,
            ..
        }) => created.starts_with("/dev/shm/"),
        _ => false,
    }));
    Ok(())
}


#[test]
fn every_captured_bind_mount_line_is_still_reported_and_the_full_path_ones_flagged() -> TestResult {
    let declared = sets()?;
    let events: Vec<(bool, Option<FimEvent>)> = BIND_LINES
        .lines()
        .map(|line| {
            let full = FULL_POLICIES.iter().any(|policy| line.contains(policy));
            (full, classify(line, MAX_EVENT_LINE_BYTES, &policies(), &declared))
        })
        .collect();
    assert_eq!(events.len(), BIND_COUNT);
    assert!(events
        .iter()
        .all(|(full, event)| event.is_some() && *full == (event.as_ref().is_some_and(flagged))));
    assert_eq!(events.iter().filter(|(full, _)| *full).count(), BIND_FULL_COUNT);
    Ok(())
}


fn flagged(event: &FimEvent) -> bool {
    matches!(
        event,
        FimEvent::Write { mount_ambiguous: true, .. }
            | FimEvent::Rename {
                mount_ambiguous: true,
                honeytoken: false,
                ..
            }
            | FimEvent::Link {
                mount_ambiguous: true,
                honeytoken: false,
                ..
            }
    )
}


#[test]
fn a_declared_joined_path_is_never_flagged_and_an_undeclared_dentry_never_matters() -> TestResult {
    let moved_in = json!([named("/usr/bin/x"), named("/etc/cron.d")]);
    assert_eq!(
        classified("ostyr-fimp-server", "security_path_unlink", &moved_in)?,
        write_of("/etc/cron.d/x", false)
    );
    let elsewhere = json!([named("/tmp/x"), named("/dev/shm")]);
    assert_eq!(
        classified("ostyr-fimp-server", "security_path_unlink", &elsewhere)?,
        write_of("/dev/shm/x", false)
    );
    Ok(())
}


const NS_LINES: &str = include_str!("../fixtures/ns-lines.jsonl");


const NS_FOREIGN_LINES: &str = include_str!("../fixtures/ns-foreign-lines.jsonl");


const NS_COUNT: usize = 18;


#[test]
fn the_captured_private_namespace_lines_of_an_unprivileged_user_are_never_honeytokens() -> TestResult {
    let declared = sets()?;
    let host: Vec<Option<FimEvent>> = NS_LINES
        .lines()
        .map(|line| classify(line, MAX_EVENT_LINE_BYTES, &policies(), &declared))
        .collect();
    assert_eq!(host.len(), NS_COUNT);
    assert!(host
        .iter()
        .all(|event| !matches!(event, Some(FimEvent::Honeytoken { .. }) | Some(FimEvent::Rename { honeytoken: true, .. }))));
    let foreign: Vec<Option<FimEvent>> = NS_FOREIGN_LINES
        .lines()
        .map(|line| classify(line, MAX_EVENT_LINE_BYTES, &policies(), &declared))
        .collect();
    assert_eq!(foreign.len(), NS_COUNT);
    assert!(foreign.iter().all(|event| matches!(
        event,
        Some(FimEvent::Write { foreign_mount_ns: true, .. })
            | Some(FimEvent::Rename {
                foreign_mount_ns: true,
                honeytoken: false,
                ..
            })
    )));
    Ok(())
}


#[test]
fn a_foreign_twin_never_gives_honeytoken_severity_for_any_hook() -> TestResult {
    let token_dir = json!([named("/root"), named("/passwords.txt")]);
    let rename_args = json!([named("/root"), named("/passwords.txt"), named("/root"), named("/moved")]);
    let unresolved_args = json!([unresolved(), unresolved(), named("/root"), named("/moved")]);
    let link_args = json!([named("/x"), named("/root"), named("/passwords.txt")]);
    let reversed_link_args = json!([named("/root"), named("/passwords.txt"), named("/x")]);
    let flagged_rename = |event: Option<FimEvent>| {
        matches!(
            event,
            Some(FimEvent::Rename {
                honeytoken: false,
                foreign_mount_ns: true,
                ..
            })
        )
    };
    let flagged_link = |event: Option<FimEvent>| {
        matches!(
            event,
            Some(FimEvent::Link {
                honeytoken: false,
                foreign_mount_ns: true,
                ..
            })
        )
    };
    assert!(flagged_rename(classified("ostyr-fimtf-server", "security_path_rename", &rename_args)?));
    assert!(flagged_rename(classified("ostyr-fimuf-server", "security_path_rename", &rename_args)?));
    assert!(flagged_rename(classified(
        "ostyr-fimuf-server",
        "security_path_rename",
        &unresolved_args
    )?));
    assert!(flagged_link(classified("ostyr-fimtf-server", "security_path_link", &link_args)?));
    assert!(flagged_link(classified("ostyr-fimuf-server", "security_path_link", &reversed_link_args)?));
    assert!(flagged_link(classified("ostyr-fimvf-server", "security_path_link", &reversed_link_args)?));
    ["security_path_unlink", "security_path_rmdir"]
        .iter()
        .try_for_each(|hook| -> TestResult {
            let removal = classified("ostyr-fimtf-server", hook, &token_dir)?;
            assert!(matches!(
                removal,
                Some(FimEvent::Write {
                    foreign_mount_ns: true,
                    name_match: true,
                    ..
                })
            ));
            let full = classified("ostyr-fimqf-server", hook, &json!([named("/passwords.txt"), named("/root")]))?;
            assert!(matches!(full, Some(FimEvent::Write { foreign_mount_ns: true, .. })));
            Ok(())
        })?;
    let missing = classified("ostyr-fimof-server", "security_file_open", &json!([]))?;
    assert!(matches!(missing, Some(FimEvent::MissingPath { .. })));
    let token = json!([{"file_arg": {"path": "/root/passwords.txt"}}]);
    let open = classified("ostyr-fimof-server", "security_file_open", &token)?;
    assert!(matches!(
        open,
        Some(FimEvent::Write {
            foreign_mount_ns: true,
            name_match: false,
            ..
        })
    ));
    let host_open = classified("ostyr-fim-server", "security_file_open", &token)?;
    assert!(matches!(host_open, Some(FimEvent::Honeytoken { .. })));
    Ok(())
}
