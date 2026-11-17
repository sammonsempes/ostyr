use crate::support::role;
use crate::types::TestResult;
use linux_fim::classify::classify;
use linux_fim::limits::{MAX_EVENT_LINE_BYTES, UNRESOLVED_NAME};
use linux_fim::model::{FimEvent, Honeytoken, HoneytokenKind, WatchKind, WatchSets};
use linux_fim::policy::{policy_names, watch_sets};
use serde_json::json;


const ALICE: u32 = 1001;


const BOB: u32 = 1002;


const ROOT: u32 = 0;


fn owned_sets() -> WatchSets {
    let mut planted = role("a", &[("/etc/passwd", WatchKind::File)], &["/root/passwords.txt"]);
    planted.honeytokens.push(Honeytoken {
        path: "/home/bob/.aws/credentials".to_string(),
        kind: HoneytokenKind::AwsCredentials,
        owner_uid: BOB,
    });
    watch_sets(&planted)
}


fn line(policy: &str, function: &str, args: &serde_json::Value, euid: Option<u32>) -> String {
    let process = euid.map_or_else(
        || json!({"binary": "/usr/bin/cat"}),
        |uid| json!({"binary": "/usr/bin/cat", "process_credentials": {"euid": uid}}),
    );
    json!({"process_kprobe": {"policy_name": policy, "function_name": function, "args": args, "process": process}}).to_string()
}


fn kprobe_event(policy: &str, function: &str, args: &serde_json::Value, euid: Option<u32>) -> Option<FimEvent> {
    classify(
        &line(policy, function, args, euid),
        MAX_EVENT_LINE_BYTES,
        &policy_names("a"),
        &owned_sets(),
    )
}


fn opened(path: &str, euid: Option<u32>) -> Option<FimEvent> {
    kprobe_event("ostyr-fim-a", "security_file_open", &json!([{"file_arg": {"path": path}}]), euid)
}


fn named(path: &str) -> serde_json::Value {
    json!({"path_arg": {"path": path}})
}


fn unresolved() -> serde_json::Value {
    json!({"path_arg": {"flags": "unresolvedPathComponents"}})
}


fn is_honeytoken_open(found: &Option<FimEvent>) -> bool {
    matches!(found, Some(FimEvent::Honeytoken { .. }))
}


fn is_flagged_write(found: &Option<FimEvent>) -> bool {
    matches!(
        found,
        Some(FimEvent::Write {
            mount_ambiguous: true,
            foreign_mount_ns: false,
            dentry_path: None,
            ..
        })
    )
}


#[test]
fn root_and_the_planted_owner_reach_a_honeytoken_others_do_not() -> TestResult {
    assert!(is_honeytoken_open(&opened("/root/passwords.txt", Some(ROOT))));
    assert!(is_honeytoken_open(&opened("/home/bob/.aws/credentials", Some(BOB))));
    assert!(is_flagged_write(&opened("/root/passwords.txt", Some(ALICE))));
    assert!(is_flagged_write(&opened("/root/passwords.txt", Some(BOB))));
    assert!(is_flagged_write(&opened("/home/bob/.aws/credentials", Some(ALICE))));
    Ok(())
}


#[test]
fn a_missing_credential_is_never_a_honeytoken() -> TestResult {
    assert!(is_flagged_write(&opened("/root/passwords.txt", None)));
    Ok(())
}


#[test]
fn a_flagged_open_keeps_the_path_as_rendered() -> TestResult {
    assert!(matches!(
        opened("/root/passwords.txt", Some(ALICE)),
        Some(FimEvent::Write { path, process, name_match: false, .. }) if path == "/root/passwords.txt" && process == "/usr/bin/cat"
    ));
    Ok(())
}


#[test]
fn a_removal_of_a_honeytoken_needs_a_uid_that_reaches_it() -> TestResult {
    let args = json!([named("/root"), named("/passwords.txt")]);
    ["security_path_unlink", "security_path_rmdir"].iter().for_each(|hook| {
        assert!(is_honeytoken_open(&kprobe_event("ostyr-fimt-a", hook, &args, Some(ROOT))));
        assert!(matches!(
            kprobe_event("ostyr-fimt-a", hook, &args, Some(ALICE)),
            Some(FimEvent::Write {
                mount_ambiguous: true,
                name_match: true,
                foreign_mount_ns: false,
                ..
            })
        ));
        assert!(matches!(
            kprobe_event("ostyr-fimt-a", hook, &args, None),
            Some(FimEvent::Write { mount_ambiguous: true, .. })
        ));
    });
    Ok(())
}


#[test]
fn a_removal_of_something_else_is_not_flagged_as_ambiguous() -> TestResult {
    let args = json!([named("/tmp"), named("/other")]);
    assert!(matches!(
        kprobe_event("ostyr-fimt-a", "security_path_unlink", &args, Some(ALICE)),
        Some(FimEvent::Write { mount_ambiguous: false, .. })
    ));
    Ok(())
}


#[test]
fn a_rename_of_a_honeytoken_needs_a_uid_that_reaches_it() -> TestResult {
    let moved = json!([named("/root"), named("/passwords.txt"), named("/root"), named("/moved")]);
    let back = json!([named("/root"), named("/moved"), named("/root"), named("/passwords.txt")]);
    [&moved, &back].iter().for_each(|args| {
        assert!(matches!(
            kprobe_event("ostyr-fimt-a", "security_path_rename", args, Some(ROOT)),
            Some(FimEvent::Rename {
                honeytoken: true,
                mount_ambiguous: false,
                ..
            })
        ));
        assert!(matches!(
            kprobe_event("ostyr-fimt-a", "security_path_rename", args, Some(ALICE)),
            Some(FimEvent::Rename {
                honeytoken: false,
                mount_ambiguous: true,
                foreign_mount_ns: false,
                ..
            })
        ));
        assert!(matches!(
            kprobe_event("ostyr-fimt-a", "security_path_rename", args, None),
            Some(FimEvent::Rename {
                honeytoken: false,
                mount_ambiguous: true,
                ..
            })
        ));
    });
    let unrelated = json!([named("/tmp"), named("/a"), named("/tmp"), named("/b")]);
    assert!(matches!(
        kprobe_event("ostyr-fimt-a", "security_path_rename", &unrelated, Some(ALICE)),
        Some(FimEvent::Rename {
            honeytoken: false,
            mount_ambiguous: false,
            ..
        })
    ));
    Ok(())
}


#[test]
fn an_unresolved_side_is_trusted_for_the_planted_owner_or_root_only() -> TestResult {
    let args = json!([unresolved(), unresolved(), named("/root"), named("/moved")]);
    let owner_only = json!([unresolved(), unresolved(), named("/home/bob/.aws"), named("/moved")]);
    assert!(matches!(
        kprobe_event("ostyr-fimt-a", "security_path_rename", &args, Some(ROOT)),
        Some(FimEvent::Rename { honeytoken: true, .. })
    ));
    assert!(matches!(
        kprobe_event("ostyr-fimt-a", "security_path_rename", &owner_only, Some(BOB)),
        Some(FimEvent::Rename { honeytoken: true, .. })
    ));
    assert!(matches!(
        kprobe_event("ostyr-fimt-a", "security_path_rename", &args, Some(ALICE)),
        Some(FimEvent::Rename {
            honeytoken: false,
            mount_ambiguous: true,
            ..
        })
    ));
    assert_eq!(UNRESOLVED_NAME, "[unresolved]");
    Ok(())
}


#[test]
fn a_link_created_at_a_honeytoken_needs_a_uid_that_reaches_it() -> TestResult {
    let args = json!([named("/x"), named("/root"), named("/passwords.txt")]);
    assert!(matches!(
        kprobe_event("ostyr-fimt-a", "security_path_link", &args, Some(ROOT)),
        Some(FimEvent::Link {
            honeytoken: true,
            mount_ambiguous: false,
            ..
        })
    ));
    assert!(matches!(
        kprobe_event("ostyr-fimt-a", "security_path_link", &args, Some(ALICE)),
        Some(FimEvent::Link {
            honeytoken: false,
            mount_ambiguous: true,
            foreign_mount_ns: false,
            ..
        })
    ));
    assert!(matches!(
        kprobe_event("ostyr-fimt-a", "security_path_link", &args, None),
        Some(FimEvent::Link {
            honeytoken: false,
            mount_ambiguous: true,
            ..
        })
    ));
    Ok(())
}


#[test]
fn a_user_namespace_twin_is_flagged_foreign_whatever_the_uid() -> TestResult {
    let open = json!([{"file_arg": {"path": "/root/passwords.txt"}}]);
    let moved = json!([named("/root"), named("/passwords.txt"), named("/root"), named("/moved")]);
    [ROOT, ALICE].iter().for_each(|uid| {
        assert!(matches!(
            kprobe_event("ostyr-fimow-a", "security_file_open", &open, Some(*uid)),
            Some(FimEvent::Write {
                foreign_mount_ns: true,
                mount_ambiguous: false,
                ..
            })
        ));
        assert!(matches!(
            kprobe_event("ostyr-fimtw-a", "security_path_rename", &moved, Some(*uid)),
            Some(FimEvent::Rename {
                foreign_mount_ns: true,
                honeytoken: false,
                ..
            })
        ));
        assert!(matches!(
            kprobe_event("ostyr-fimuw-a", "security_path_rename", &moved, Some(*uid)),
            Some(FimEvent::Rename {
                foreign_mount_ns: true,
                honeytoken: false,
                ..
            })
        ));
        assert!(matches!(
            kprobe_event(
                "ostyr-fimpw-a",
                "security_path_unlink",
                &json!([named("/passwords.txt"), named("/root")]),
                Some(*uid)
            ),
            Some(FimEvent::Write { foreign_mount_ns: true, .. })
        ));
    });
    Ok(())
}
