use crate::support::role;
use crate::types::TestResult;
use linux_fim::classify::classify;
use linux_fim::limits::MAX_EVENT_LINE_BYTES;
use linux_fim::model::{FimEvent, WatchSets};
use linux_fim::policy::{policy_names, watch_sets};


const CHROOT_LINES: &str = include_str!("../fixtures/chroot-lines.jsonl");


const PROCROOT_LINES: &str = include_str!("../fixtures/procroot-lines.jsonl");


const ALICE_OPEN: &str = include_str!("../fixtures/alice-open.json");


const ROOT_OPEN: &str = include_str!("../fixtures/root-open.json");


const CHROOT_COUNT: usize = 18;


const PROCROOT_COUNT: usize = 2;


const ALICE: u32 = 1001;


const ROOT: u32 = 0;


fn server_sets(owner: u32) -> WatchSets {
    let mut planted = role("server", &[], &["/root/passwords.txt", "/root/.aws/credentials"]);
    planted.honeytokens.iter_mut().for_each(|token| token.owner_uid = owner);
    watch_sets(&planted)
}


fn classified_lines(text: &str, sets: &WatchSets) -> Vec<Option<FimEvent>> {
    text.lines()
        .map(|captured| classify(captured, MAX_EVENT_LINE_BYTES, &policy_names("server"), sets))
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
    let events = classified_lines(CHROOT_LINES, &server_sets(ROOT));
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
    let events = classified_lines(PROCROOT_LINES, &server_sets(ROOT));
    assert_eq!(events.len(), PROCROOT_COUNT);
    assert!(events.iter().all(is_flagged_write));
    Ok(())
}


#[test]
fn the_captured_opens_follow_the_planted_owner() -> TestResult {
    let root_owned = server_sets(ROOT);
    let alice_owned = server_sets(ALICE);
    assert!(classified_lines(ROOT_OPEN, &root_owned).iter().all(is_honeytoken));
    assert!(classified_lines(ROOT_OPEN, &alice_owned).iter().all(is_honeytoken));
    assert!(classified_lines(ALICE_OPEN, &root_owned).iter().all(is_flagged_write));
    assert!(classified_lines(ALICE_OPEN, &alice_owned).iter().all(is_honeytoken));
    assert!(classified_lines(PROCROOT_LINES, &alice_owned).iter().all(is_honeytoken));
    Ok(())
}
