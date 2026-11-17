use crate::support::role;
use crate::types::TestResult;
use linux_fim::classify::classify;
use linux_fim::limits::{MAX_EVENT_LINE_BYTES, UNRESOLVED_NAME};
use linux_fim::model::{FimEvent, PlantedIdentity, WatchKind, WatchSets};
use linux_fim::policy::{kernel_device, policy_names, watch_sets, with_planted};
use serde_json::json;


const DEVICE: u32 = 265_289_729;


const OTHER_DEVICE: u32 = 43;


const TOKEN_INODE: u64 = 4_708;


const BOB_INODE: u64 = 5_099;


const FAKE_INODE: u64 = 7;


const ROOT_DIR_INODE: u64 = 1_692;


const STAT_ROOT_DEVICE: u64 = 0xfd01;


const STAT_SMALL_MINOR: u64 = 0x0801;


const STAT_WIDE_MINOR: u64 = 0x0800 | 0x34 | (0x1200 << 12);


const SCSI_MAJOR: u32 = 8;


const KERNEL_MINOR_BITS: u32 = 20;


const WIDE_MINOR: u32 = 0x1234;


fn planted_sets() -> WatchSets {
    let sets = watch_sets(&role(
        "a",
        &[("/etc/passwd", WatchKind::File)],
        &["/root/passwords.txt", "/home/bob/.aws/credentials"],
    ));
    with_planted(
        sets,
        vec![
            PlantedIdentity {
                path: "/root/passwords.txt".to_string(),
                device: DEVICE,
                inode: TOKEN_INODE,
            },
            PlantedIdentity {
                path: "/home/bob/.aws/credentials".to_string(),
                device: DEVICE,
                inode: BOB_INODE,
            },
            PlantedIdentity {
                path: "/root".to_string(),
                device: DEVICE,
                inode: ROOT_DIR_INODE,
            },
        ],
    )
}


fn identity(device: u32, inode: u64) -> Vec<serde_json::Value> {
    vec![json!({"size_arg": inode.to_string()}), json!({"uint_arg": device})]
}


fn line(policy: &str, function: &str, args: &[serde_json::Value], trailing: &[serde_json::Value]) -> String {
    let listed: Vec<serde_json::Value> = args.iter().chain(trailing.iter()).cloned().collect();
    json!({"process_kprobe": {"policy_name": policy, "function_name": function, "args": listed, "process": {"binary": "/usr/bin/cat"}}}).to_string()
}


fn event(policy: &str, function: &str, args: &[serde_json::Value], trailing: &[serde_json::Value]) -> Option<FimEvent> {
    classify(
        &line(policy, function, args, trailing),
        MAX_EVENT_LINE_BYTES,
        &policy_names("a"),
        &planted_sets(),
    )
}


fn named(path: &str) -> serde_json::Value {
    json!({"path_arg": {"path": path}})
}


fn opened(path: &str) -> serde_json::Value {
    json!({"file_arg": {"path": path}})
}


fn is_honeytoken(found: &Option<FimEvent>) -> bool {
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


fn unproven() -> Vec<Vec<serde_json::Value>> {
    vec![
        identity(DEVICE, FAKE_INODE),
        identity(OTHER_DEVICE, TOKEN_INODE),
        vec![],
        vec![json!({"uint_arg": DEVICE})],
        vec![
            json!({"error_arg": {"Message": "Bad address encountered during resolve dereference at depth 1"}}),
            json!({"uint_arg": DEVICE}),
        ],
        vec![json!({"size_arg": "not a number"}), json!({"uint_arg": DEVICE})],
        vec![json!({"size_arg": TOKEN_INODE.to_string()}), json!({"size_arg": DEVICE.to_string()})],
    ]
}


#[test]
fn an_open_is_a_honeytoken_only_when_the_identity_is_a_planted_one() -> TestResult {
    let args = [opened("/root/passwords.txt")];
    assert!(is_honeytoken(&event(
        "ostyr-fim-a",
        "security_file_open",
        &args,
        &identity(DEVICE, TOKEN_INODE)
    )));
    unproven()
        .iter()
        .for_each(|trailing| assert!(is_flagged_write(&event("ostyr-fim-a", "security_file_open", &args, trailing))));
    Ok(())
}


#[test]
fn a_planted_identity_proves_only_the_path_it_was_recorded_for() -> TestResult {
    let args = [opened("/root/passwords.txt")];
    assert!(!is_honeytoken(&event(
        "ostyr-fim-a",
        "security_file_open",
        &args,
        &identity(DEVICE, BOB_INODE)
    )));
    assert!(is_honeytoken(&event(
        "ostyr-fim-a",
        "security_file_open",
        &[opened("/home/bob/.aws/credentials")],
        &identity(DEVICE, BOB_INODE)
    )));
    Ok(())
}


#[test]
fn a_directory_identity_never_proves_an_open() -> TestResult {
    let args = [opened("/root/passwords.txt")];
    assert!(is_flagged_write(&event(
        "ostyr-fim-a",
        "security_file_open",
        &args,
        &identity(DEVICE, ROOT_DIR_INODE)
    )));
    assert!(is_flagged_write(&event(
        "ostyr-fim-a",
        "security_file_open",
        &[opened("/root")],
        &identity(DEVICE, ROOT_DIR_INODE)
    )));
    Ok(())
}


#[test]
fn an_ancestor_identity_proves_a_rename_of_that_ancestor_only() -> TestResult {
    let ancestor = [named("/"), named("/root"), named("/moved")];
    let token = [named("/root"), named("/passwords.txt"), named("/moved")];
    assert!(matches!(
        event("ostyr-fimt-a", "security_path_rename", &ancestor, &identity(DEVICE, ROOT_DIR_INODE)),
        Some(FimEvent::Rename { honeytoken: true, .. })
    ));
    assert!(matches!(
        event("ostyr-fimt-a", "security_path_rename", &token, &identity(DEVICE, ROOT_DIR_INODE)),
        Some(FimEvent::Rename {
            honeytoken: false,
            mount_ambiguous: true,
            ..
        })
    ));
    assert!(matches!(
        event("ostyr-fimt-a", "security_path_rename", &ancestor, &identity(DEVICE, TOKEN_INODE)),
        Some(FimEvent::Rename {
            honeytoken: false,
            mount_ambiguous: true,
            ..
        })
    ));
    Ok(())
}


#[test]
fn a_flagged_open_keeps_the_path_as_rendered() -> TestResult {
    let args = [opened("/root/passwords.txt")];
    assert!(matches!(
        event("ostyr-fim-a", "security_file_open", &args, &identity(DEVICE, FAKE_INODE)),
        Some(FimEvent::Write { path, process, name_match: false, .. }) if path == "/root/passwords.txt" && process == "/usr/bin/cat"
    ));
    Ok(())
}


#[test]
fn a_removal_of_a_honeytoken_needs_the_planted_identity() -> TestResult {
    let args = [named("/root"), named("/passwords.txt")];
    ["security_path_unlink", "security_path_rmdir"].iter().for_each(|hook| {
        assert!(is_honeytoken(&event("ostyr-fimt-a", hook, &args, &identity(DEVICE, TOKEN_INODE))));
        unproven().iter().for_each(|trailing| {
            assert!(matches!(
                event("ostyr-fimt-a", hook, &args, trailing),
                Some(FimEvent::Write {
                    mount_ambiguous: true,
                    name_match: true,
                    foreign_mount_ns: false,
                    ..
                })
            ));
        });
    });
    Ok(())
}


#[test]
fn a_removal_of_something_else_is_not_flagged_as_ambiguous() -> TestResult {
    let args = [named("/tmp"), named("/other")];
    assert!(matches!(
        event("ostyr-fimt-a", "security_path_unlink", &args, &identity(DEVICE, FAKE_INODE)),
        Some(FimEvent::Write { mount_ambiguous: false, .. })
    ));
    Ok(())
}


#[test]
fn a_rename_of_the_matched_honeytoken_needs_the_planted_identity() -> TestResult {
    let moved = [named("/root"), named("/passwords.txt"), named("/moved")];
    let back = [named("/root"), named("/passwords.txt"), named("/moved")];
    assert!(matches!(
        event("ostyr-fimt-a", "security_path_rename", &moved, &identity(DEVICE, TOKEN_INODE)),
        Some(FimEvent::Rename {
            honeytoken: true,
            mount_ambiguous: false,
            source,
            target,
            ..
        }) if source == "/root/passwords.txt" && target == "/moved"
    ));
    assert!(matches!(
        event("ostyr-fimu-a", "security_path_rename", &back, &identity(DEVICE, TOKEN_INODE)),
        Some(FimEvent::Rename {
            honeytoken: true,
            source,
            target,
            ..
        }) if source == "/moved" && target == "/root/passwords.txt"
    ));
    unproven().iter().for_each(|trailing| {
        assert!(matches!(
            event("ostyr-fimt-a", "security_path_rename", &moved, trailing),
            Some(FimEvent::Rename {
                honeytoken: false,
                mount_ambiguous: true,
                foreign_mount_ns: false,
                ..
            })
        ));
        assert!(matches!(
            event("ostyr-fimu-a", "security_path_rename", &back, trailing),
            Some(FimEvent::Rename {
                honeytoken: false,
                mount_ambiguous: true,
                ..
            })
        ));
    });
    let unrelated = [named("/tmp"), named("/a"), named("/b")];
    assert!(matches!(
        event("ostyr-fimt-a", "security_path_rename", &unrelated, &identity(DEVICE, FAKE_INODE)),
        Some(FimEvent::Rename {
            honeytoken: false,
            mount_ambiguous: false,
            ..
        })
    ));
    Ok(())
}


#[test]
fn an_unresolved_side_cannot_be_proven_by_an_identity() -> TestResult {
    let unresolved = json!({"path_arg": {"flags": "unresolvedPathComponents"}});
    let args = [unresolved.clone(), unresolved, named("/moved")];
    [identity(DEVICE, TOKEN_INODE), identity(DEVICE, FAKE_INODE)].iter().for_each(|trailing| {
        assert!(matches!(
            event("ostyr-fimt-a", "security_path_rename", &args, trailing),
            Some(FimEvent::Rename {
                honeytoken: false,
                mount_ambiguous: true,
                source,
                ..
            }) if source == UNRESOLVED_NAME
        ));
    });
    Ok(())
}


#[test]
fn a_link_created_at_a_honeytoken_needs_the_planted_identity() -> TestResult {
    let args = [named("/x"), named("/root"), named("/passwords.txt")];
    assert!(matches!(
        event("ostyr-fimt-a", "security_path_link", &args, &identity(DEVICE, TOKEN_INODE)),
        Some(FimEvent::Link {
            honeytoken: true,
            mount_ambiguous: false,
            ..
        })
    ));
    unproven().iter().for_each(|trailing| {
        assert!(matches!(
            event("ostyr-fimt-a", "security_path_link", &args, trailing),
            Some(FimEvent::Link {
                honeytoken: false,
                mount_ambiguous: true,
                foreign_mount_ns: false,
                ..
            })
        ));
    });
    Ok(())
}


#[test]
fn a_twin_is_flagged_foreign_whatever_the_identity() -> TestResult {
    let open = [opened("/root/passwords.txt")];
    let moved = [named("/root"), named("/passwords.txt"), named("/moved")];
    [identity(DEVICE, TOKEN_INODE), identity(DEVICE, FAKE_INODE)].iter().for_each(|trailing| {
        ["ostyr-fimof-a", "ostyr-fimow-a"].iter().for_each(|policy| {
            assert!(matches!(
                event(policy, "security_file_open", &open, trailing),
                Some(FimEvent::Write {
                    foreign_mount_ns: true,
                    mount_ambiguous: false,
                    ..
                })
            ));
        });
        ["ostyr-fimtf-a", "ostyr-fimtw-a", "ostyr-fimuf-a", "ostyr-fimuw-a"]
            .iter()
            .for_each(|policy| {
                assert!(matches!(
                    event(policy, "security_path_rename", &moved, trailing),
                    Some(FimEvent::Rename {
                        foreign_mount_ns: true,
                        honeytoken: false,
                        ..
                    })
                ));
            });
        assert!(matches!(
            event(
                "ostyr-fimpw-a",
                "security_path_unlink",
                &[named("/passwords.txt"), named("/root")],
                trailing
            ),
            Some(FimEvent::Write { foreign_mount_ns: true, .. })
        ));
    });
    Ok(())
}


#[test]
fn a_stat_device_is_turned_into_the_kernel_device() -> TestResult {
    assert_eq!(kernel_device(STAT_ROOT_DEVICE), DEVICE);
    assert_eq!(kernel_device(STAT_SMALL_MINOR), (SCSI_MAJOR << KERNEL_MINOR_BITS) | 1);
    assert_eq!(kernel_device(STAT_WIDE_MINOR), (SCSI_MAJOR << KERNEL_MINOR_BITS) | WIDE_MINOR);
    Ok(())
}
