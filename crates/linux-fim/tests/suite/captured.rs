use crate::support::{planted, role};
use crate::types::TestResult;
use linux_fim::classify::classify;
use linux_fim::limits::MAX_EVENT_LINE_BYTES;
use linux_fim::model::{FimEvent, PlantedIdentity, WatchSets};
use linux_fim::policy::{policy_names, watch_sets, with_planted};


const CHROOT_LINES: &str = include_str!("../fixtures/chroot-lines.jsonl");


const PROCROOT_LINES: &str = include_str!("../fixtures/procroot-lines.jsonl");


const ALICE_OPEN: &str = include_str!("../fixtures/alice-open.json");


const ROOT_OPEN: &str = include_str!("../fixtures/root-open.json");


const BOB_OPEN: &str = include_str!("../fixtures/bob-open.json");


const SSHD_LINES: &str = include_str!("../fixtures/sshd-lines.jsonl");


const CHROOT_COUNT: usize = 18;


const PROCROOT_COUNT: usize = 2;


const SSHD_COUNT: usize = 3;


const KERNEL_DEVICE: u32 = 265_289_729;


const BOB_INODE: u64 = 524_323;


fn server_sets() -> WatchSets {
    planted(watch_sets(&role("server", &[], &["/root/passwords.txt", "/root/.aws/credentials"])))
}


fn lab_sets() -> WatchSets {
    let sets = watch_sets(&role("lab", &[], &["/root/passwords.txt", "/home/bob/.aws/credentials"]));
    with_planted(
        sets,
        vec![PlantedIdentity {
            path: "/home/bob/.aws/credentials".to_string(),
            device: KERNEL_DEVICE,
            inode: BOB_INODE,
        }],
    )
}


fn classified_lines(text: &str, sets: &WatchSets) -> Vec<Option<FimEvent>> {
    let policies: Vec<String> = policy_names("server").into_iter().chain(policy_names("lab")).collect();
    text.lines()
        .map(|captured| classify(captured, MAX_EVENT_LINE_BYTES, &policies, sets))
        .collect()
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
            ..
        })
    )
}


#[test]
fn the_captured_chroot_forgeries_are_never_honeytokens() -> TestResult {
    let events = classified_lines(CHROOT_LINES, &server_sets());
    assert_eq!(events.len(), CHROOT_COUNT);
    assert!(events.iter().all(|found| matches!(
        found,
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
fn the_captured_proc_root_opens_are_flagged_not_honeytokens() -> TestResult {
    let events = classified_lines(PROCROOT_LINES, &server_sets());
    assert_eq!(events.len(), PROCROOT_COUNT);
    assert!(events.iter().all(is_flagged_write));
    assert!(classified_lines(ALICE_OPEN, &server_sets()).iter().all(is_flagged_write));
    Ok(())
}


#[test]
fn the_captured_root_and_owner_opens_of_the_real_files_are_honeytokens() -> TestResult {
    assert!(classified_lines(ROOT_OPEN, &server_sets()).iter().all(is_honeytoken));
    assert!(classified_lines(BOB_OPEN, &lab_sets()).iter().all(is_honeytoken));
    assert!(classified_lines(BOB_OPEN, &server_sets()).iter().all(is_flagged_write));
    Ok(())
}


#[test]
fn the_captured_root_daemon_opens_through_user_symlinks_are_flagged() -> TestResult {
    let events = classified_lines(SSHD_LINES, &lab_sets());
    assert_eq!(events.len(), SSHD_COUNT);
    assert!(events.iter().all(is_flagged_write));
    assert!(events
        .iter()
        .all(|found| matches!(found, Some(FimEvent::Write { process, .. }) if process == "/usr/sbin/sshd")));
    Ok(())
}
