#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/types.rs"]
mod types;


use fixtures::{data, guest, node, set, storage, value};
use serde_json::Value;
use types::TestResult;
use virt_inventory::diff::diff;
use virt_inventory::error::ParseError;
use virt_inventory::inventory::build_inventory;
use virt_inventory::limits::Limits;
use virt_inventory::model::{ItemKey, Parsed, ResourceKind};
use virt_inventory::proxmox::{parse_permissions, parse_resources, valid_acl_path, valid_display_name};


const SEGMENT_MAX: usize = 64;


const SEGMENTS_MAX: usize = 8;


const NODE_MAX: usize = 63;


const ACCEPTED_NODES: usize = 4;


const ACCEPTED_STORAGES: usize = 3;


const VMID_BASE: usize = 100;


const LOST_KEYS: usize = 2;


fn parsed_of(items: Vec<Value>) -> Result<Parsed, ParseError> {
    parse_resources(data(items).as_slice(), &Limits::default())
}


fn qemu_key() -> ItemKey {
    ItemKey {
        kind: ResourceKind::Qemu,
        key: "100".to_owned(),
    }
}


#[test]
fn look_alike_node_names_are_refused() -> TestResult {
    let names = ["pve\u{3164}", "pve\u{a0}", "pve ", "\u{440}ve", "-pve", "pve-", "", "a_b", "a.b"];
    let parsed = parsed_of(names.iter().map(|name| node(name)).collect())?;
    assert!(parsed.items.is_empty());
    assert_eq!((parsed.skipped.bad_field, parsed.skipped.key_lost), (names.len(), names.len()));
    let accepted = parsed_of(vec![node("pve"), node("pve-2"), node("a"), node(&"a".repeat(NODE_MAX))])?;
    assert_eq!(accepted.items.len(), ACCEPTED_NODES);
    let too_long = parsed_of(vec![node(&"a".repeat(NODE_MAX + 1))])?;
    assert_eq!(too_long.skipped.bad_field, 1);
    Ok(())
}


#[test]
fn look_alike_storage_ids_are_refused() -> TestResult {
    let ids = ["lvm\u{3164}", "lvm ", "-lvm", "1lvm", "", "l/vm", "l\u{430}"];
    let parsed = parsed_of(ids.iter().map(|id| storage("pve", id)).collect())?;
    assert!(parsed.items.is_empty());
    assert_eq!(parsed.skipped.bad_field, ids.len());
    let accepted = parsed_of(vec![
        storage("pve", "local-lvm"),
        storage("pve", "a.b_c"),
        storage("pve", &"a".repeat(SEGMENT_MAX)),
    ])?;
    assert_eq!(accepted.items.len(), ACCEPTED_STORAGES);
    let too_long = parsed_of(vec![storage("pve", &"a".repeat(SEGMENT_MAX + 1))])?;
    assert_eq!(too_long.skipped.bad_field, 1);
    Ok(())
}


#[test]
fn look_alike_acl_paths_are_refused() -> TestResult {
    let good = ["/", "/vms/100", "/storage/local-lvm", "/access/groups", "/a/b@pve/c:d.e_f"];
    good.iter().for_each(|path| assert!(valid_acl_path(path), "{path}"));
    let long = format!("/{}", "a".repeat(SEGMENT_MAX + 1));
    let deep = "/a".repeat(SEGMENTS_MAX + 1);
    let bad = [
        "/vms/100\u{3164}",
        "vms",
        "",
        "/vms/",
        "//",
        "/a b",
        "/a\nb",
        "/\u{430}",
        long.as_str(),
        deep.as_str(),
    ];
    bad.iter().for_each(|path| assert!(!valid_acl_path(path), "{path:?}"));
    assert!(valid_acl_path(&"/a".repeat(SEGMENTS_MAX)));
    let body = r#"{"data":{"/vms/100ㅤ":{"VM.Audit":1}}}"#;
    assert!(matches!(
        parse_permissions(body.as_bytes(), &Limits::default()),
        Err(ParseError::BadPermission)
    ));
    Ok(())
}


#[test]
fn a_look_alike_guest_name_is_dropped_and_counted_with_the_item_kept() -> TestResult {
    let names = ["web\u{3164}", "web\u{202e}", r"a\nb", "web ", " web", "a  b", ""];
    let each = names
        .iter()
        .enumerate()
        .map(|(index, name)| parsed_of(vec![guest("qemu", &(VMID_BASE + index).to_string(), name)]))
        .collect::<Result<Vec<_>, _>>()?;
    each.iter().for_each(|one| {
        assert_eq!((one.items.len(), one.skipped.name_dropped, one.skipped.bad_field), (1, 1, 0));
        assert!(one.items.iter().all(|item| item.name.is_none()));
    });
    let kept = parsed_of(vec![guest("qemu", "100", "web-1"), guest("qemu", "101", "my vm")])?;
    assert_eq!(kept.skipped.name_dropped, 0);
    assert!(valid_display_name("my vm", &Limits::default()));
    Ok(())
}


#[test]
fn a_refused_present_guest_is_unreadable_never_retired() -> TestResult {
    let previous = build_inventory("acme", "pve-1", parsed_of(vec![guest("qemu", "100", "a")])?)?;
    let mut wrong_node = guest("qemu", "100", "a");
    set(&mut wrong_node, "/node", "5")?;
    let wrong_storage = value(r#"{"type":"qemu","vmid":100,"node":"pve","storage":7}"#);
    let mut mistyped_name = guest("qemu", "100", "a");
    set(&mut mistyped_name, "/name", "[]")?;
    for element in [wrong_node, wrong_storage, mistyped_name] {
        let current = build_inventory("acme", "pve-1", parsed_of(vec![element.clone()])?)?;
        let changes = diff(&previous, &current)?;
        assert!(changes.retired.is_empty(), "retired");
        assert_eq!(changes.unreadable, vec![qemu_key()], "{element}");
    }
    let repeated_other = br#"{"data":[{"type":"qemu","vmid":100,"node":"pve","status":"a","status":"b"}]}"#;
    let kept = parse_resources(repeated_other.as_slice(), &Limits::default())?;
    assert_eq!((kept.skipped.refused_keys, kept.skipped.key_lost), (vec![qemu_key()], 0));
    let duplicate_vmid = br#"{"data":[{"type":"qemu","vmid":100,"vmid":101,"node":"pve"}]}"#;
    assert_eq!(parse_resources(duplicate_vmid.as_slice(), &Limits::default())?.skipped.key_lost, 1);
    Ok(())
}


#[test]
fn refused_node_and_storage_keys_read_only_their_own_parts() -> TestResult {
    let mut host = node("pve");
    set(&mut host, "/maxcpu", "99999999")?;
    set(&mut host, "/status", "5")?;
    let mut volume = storage("pve", "local");
    set(&mut volume, "/maxdisk", "-1")?;
    let parsed = parsed_of(vec![host, volume])?;
    let keys = parsed.skipped.refused_keys.iter().map(|key| key.key.as_str()).collect::<Vec<_>>();
    assert_eq!(keys, ["pve", "pve/local"]);
    let lost = parsed_of(vec![
        value(r#"{"type":"node","node":5,"maxcpu":99999999}"#),
        value(r#"{"type":"storage","node":"pve","storage":5,"maxdisk":-1}"#),
    ])?;
    assert_eq!(lost.skipped.key_lost, LOST_KEYS);
    Ok(())
}


const DUPLICATES: usize = 2;


const QEMU_RUN_STATES: [&str; 18] = [
    "debug",
    "inmigrate",
    "internal-error",
    "io-error",
    "paused",
    "postmigrate",
    "prelaunch",
    "finish-migrate",
    "restore-vm",
    "running",
    "save-vm",
    "shutdown",
    "suspended",
    "watchdog",
    "guest-panicked",
    "colo",
    "stopped",
    "unknown",
];


fn guests_with_status(statuses: &[&str]) -> Result<Vec<Value>, Box<dyn std::error::Error>> {
    statuses
        .iter()
        .enumerate()
        .map(|(index, text)| {
            let mut element = guest("qemu", &(VMID_BASE + index).to_string(), "a");
            set(&mut element, "/status", &Value::String((*text).to_owned()).to_string()).map(|()| element)
        })
        .collect()
}


#[test]
fn status_is_one_of_the_documented_values() -> TestResult {
    let bad = [
        "run\u{3164}",
        "Running",
        "stopped ",
        "",
        "running\u{200b}",
        "prelaunch ",
        "online",
        "Unknown",
        "unknown ",
    ];
    let parsed = parsed_of(guests_with_status(&bad)?)?;
    assert!(parsed.items.is_empty());
    assert_eq!(
        (parsed.skipped.bad_field, parsed.skipped.refused_keys.len(), parsed.skipped.key_lost),
        (bad.len(), bad.len(), 0)
    );
    assert_eq!(parsed_of(guests_with_status(&QEMU_RUN_STATES)?)?.items.len(), QEMU_RUN_STATES.len());
    Ok(())
}


#[test]
fn a_zero_width_status_is_unreadable_never_retired() -> TestResult {
    let previous = build_inventory("acme", "pve-1", parsed_of(vec![guest("qemu", "100", "a")])?)?;
    let mut hostile = guest("qemu", "100", "a");
    set(&mut hostile, "/status", "\"running\\u200b\"")?;
    let current = build_inventory("acme", "pve-1", parsed_of(vec![hostile])?)?;
    let changes = diff(&previous, &current)?;
    assert!(changes.retired.is_empty());
    assert_eq!(changes.unreadable, vec![qemu_key()]);
    Ok(())
}


#[test]
fn node_names_are_case_folded() -> TestResult {
    let parsed = parsed_of(vec![node("PVE"), node("pve"), storage("PVE", "local"), storage("pve", "local")])?;
    let keys = parsed
        .items
        .iter()
        .map(|item| (item.node.as_str(), item.key.as_str()))
        .collect::<Vec<_>>();
    assert_eq!(keys, [("pve", "pve"), ("pve", "pve/local")]);
    assert_eq!(parsed.skipped.duplicate, DUPLICATES);
    Ok(())
}


fn status_items(kind: &str, statuses: &[&str]) -> Result<Parsed, Box<dyn std::error::Error>> {
    let items = statuses
        .iter()
        .enumerate()
        .map(|(index, text)| {
            let mut element = match kind {
                "node" => node(&format!("n{index}")),
                "storage" => storage("pve", &format!("s{index}")),
                _ => guest(kind, &(VMID_BASE + index).to_string(), "a"),
            };
            set(&mut element, "/status", &Value::String((*text).to_owned()).to_string()).map(|()| element)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(parsed_of(items)?)
}


#[test]
fn each_kind_accepts_only_its_own_statuses() -> TestResult {
    assert_eq!(status_items("lxc", &["running", "stopped", "unknown"])?.items.len(), THREE);
    assert_eq!(
        status_items("lxc", &["prelaunch", "io-error", "online", "Unknown", "unknown "])?
            .items
            .len(),
        0
    );
    assert_eq!(status_items("node", &["online", "offline", "unknown"])?.items.len(), THREE);
    assert_eq!(status_items("node", &["prelaunch", "running", "available"])?.items.len(), 0);
    assert_eq!(status_items("storage", &["available", "unknown"])?.items.len(), TWO);
    assert_eq!(status_items("storage", &["prelaunch", "online"])?.items.len(), 0);
    assert_eq!(status_items("qemu", &["io-error"])?.items.len(), 1);
    Ok(())
}


const TWO: usize = 2;


const THREE: usize = 3;


const PRELAUNCH: &[u8] = include_bytes!("fixtures/resources-prelaunch.json");


#[test]
fn a_live_prelaunch_guest_is_an_item() -> TestResult {
    let parsed = parse_resources(PRELAUNCH, &Limits::default())?;
    let status = parsed
        .items
        .iter()
        .find(|item| item.key == "9002")
        .and_then(|item| item.status.as_deref());
    assert_eq!(status, Some("prelaunch"));
    assert_eq!(parsed.skipped.bad_field, 0);
    Ok(())
}


const UNKNOWN: &[u8] = include_bytes!("fixtures/resources-unknown.json");


const UNKNOWN_GUESTS: usize = 4;


#[test]
fn a_live_unknown_answer_keeps_every_guest() -> TestResult {
    let parsed = parse_resources(UNKNOWN, &Limits::default())?;
    let unknown_guests = parsed
        .items
        .iter()
        .filter(|item| item.status.as_deref() == Some("unknown") && item.key.parse::<u64>().is_ok())
        .count();
    assert_eq!(unknown_guests, UNKNOWN_GUESTS);
    assert_eq!((parsed.skipped.bad_field, parsed.skipped.refused_keys.len()), (0, 0));
    Ok(())
}
