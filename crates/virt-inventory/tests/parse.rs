#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/reader.rs"]
mod reader;
#[path = "common/types.rs"]
mod types;


use fixtures::{data, guest, node, set, storage, value};
use reader::FailingReader;
use serde_json::Value;
use types::TestResult;
use virt_inventory::error::ParseError;
use virt_inventory::limits::Limits;
use virt_inventory::model::{ItemKey, Resource, ResourceKind, Skipped};
use virt_inventory::proxmox::parse_resources;


const SMALL_BYTES: u64 = 64;


const SMALL_ITEMS: usize = 3;


const TEXT_CAP: usize = 8;


const NEST_DEPTH: usize = 1_000_000;


const MEM: u64 = 2_147_483_648;


const DISK: u64 = 8_589_934_592;


const CPU: u64 = 2;


const VMID_BASE: u64 = 100;


const OVER_COUNT: usize = 4;


const TWO: usize = 2;


const THREE: usize = 3;


const FIVE: usize = 5;


fn parse(items: Vec<Value>) -> Result<(Vec<Resource>, Skipped), ParseError> {
    parse_resources(data(items).as_slice(), &Limits::default()).map(|parsed| (parsed.items, parsed.skipped))
}


fn key_of(kind: ResourceKind, key: &str) -> ItemKey {
    ItemKey { kind, key: key.to_owned() }
}


fn keys_of(items: &[Resource]) -> Vec<&str> {
    items.iter().map(|item| item.key.as_str()).collect()
}


fn remove(target: &mut Value, field: &str) -> Result<(), Box<dyn std::error::Error>> {
    target.as_object_mut().ok_or("not an object")?.remove(field);
    Ok(())
}


fn mutated(kind: &str, vmid: &str, pointer: &str, json_text: &str) -> Result<Value, Box<dyn std::error::Error>> {
    let mut element = guest(kind, vmid, "ok");
    set(&mut element, pointer, json_text)?;
    Ok(element)
}


#[test]
fn all_four_kinds_parse_with_their_fields() -> TestResult {
    let template = mutated("lxc", "101", "/template", "1")?;
    let (items, skipped) = parse(vec![guest("qemu", "100", "web"), template, node("pve"), storage("pve", "local")])?;
    assert_eq!(skipped, Skipped::default());
    assert_eq!(keys_of(&items), ["100", "101", "pve", "pve/local"]);
    let web = items.first().ok_or("no guest")?;
    assert_eq!(
        (web.kind, web.name.as_deref(), web.node.as_str(), web.status.as_deref()),
        (ResourceKind::Qemu, Some("web"), "pve", Some("running"))
    );
    assert_eq!(
        (web.max_cpu, web.max_mem, web.max_disk, web.template),
        (Some(CPU), Some(MEM), Some(DISK), false)
    );
    assert!(items.get(1).ok_or("no template")?.template);
    let host = items.iter().find(|item| item.kind == ResourceKind::Node).ok_or("no node")?;
    assert_eq!((host.kind, host.name.clone()), (ResourceKind::Node, None));
    let local = items.iter().find(|item| item.kind == ResourceKind::Storage).ok_or("no storage")?;
    assert_eq!(
        (local.kind, local.name.as_deref(), local.max_mem),
        (ResourceKind::Storage, Some("local"), None)
    );
    Ok(())
}


#[test]
fn other_types_and_a_missing_type_are_counted_and_skipped() -> TestResult {
    let (items, skipped) = parse(vec![
        value(r#"{"type":"pool","id":"pool/dev"}"#),
        value(r#"{"id":"sdn/x"}"#),
        value(r#"{"type":5}"#),
        guest("qemu", "100", "web"),
    ])?;
    assert_eq!(keys_of(&items), ["100"]);
    assert_eq!((skipped.other_type, skipped.unparsable, skipped.key_lost), (TWO, 1, 1));
    Ok(())
}


#[test]
fn hostile_guest_values_are_skipped_with_the_identity_kept_when_readable() -> TestResult {
    let hostile = vec![
        mutated("qemu", "100", "/name", "\"a\\u202eb\"")?,
        mutated("lxc", "101", "/name", r#""a\nb""#)?,
        mutated("qemu", "102", "/maxcpu", "65537")?,
        mutated("qemu", "103", "/maxmem", "9007199254740993")?,
        mutated("qemu", "104", "/maxdisk", "9007199254740993")?,
        mutated("qemu", "105", "/template", "2")?,
        mutated("qemu", "106", "/status", r#""-up""#)?,
        mutated("qemu", "107", "/maxcpu", "1.5")?,
    ];
    let total = hostile.len();
    let (items, skipped) = parse(hostile)?;
    assert!(items.is_empty());
    assert_eq!((skipped.bad_field, skipped.unparsable, skipped.key_lost), (total - 1, 1, 0));
    let expected = [
        (ResourceKind::Qemu, "100"),
        (ResourceKind::Lxc, "101"),
        (ResourceKind::Qemu, "102"),
        (ResourceKind::Qemu, "103"),
        (ResourceKind::Qemu, "104"),
        (ResourceKind::Qemu, "105"),
        (ResourceKind::Qemu, "106"),
        (ResourceKind::Qemu, "107"),
    ]
    .iter()
    .map(|(kind, key)| key_of(*kind, key))
    .collect::<Vec<_>>();
    assert_eq!(skipped.refused_keys, expected);
    Ok(())
}


#[test]
fn unreadable_vmids_lose_the_identity() -> TestResult {
    let hostile = vec![
        mutated("qemu", "100", "/vmid", "-1")?,
        mutated("qemu", "100", "/vmid", "1e20")?,
        mutated("qemu", "100", "/vmid", r#""100""#)?,
        mutated("qemu", "100", "/vmid", "99")?,
        mutated("qemu", "100", "/vmid", "1000000000")?,
        {
            let mut missing = guest("qemu", "100", "a");
            remove(&mut missing, "vmid")?;
            missing
        },
    ];
    let total = hostile.len();
    let (items, skipped) = parse(hostile)?;
    assert!(items.is_empty());
    assert_eq!((skipped.unparsable, skipped.bad_field, skipped.key_lost), (THREE, THREE, total));
    assert!(skipped.refused_keys.is_empty());
    Ok(())
}


#[test]
fn node_and_storage_identity_parts_are_checked() -> TestResult {
    let mut slash = node("pve");
    set(&mut slash, "/node", r#""a/b""#)?;
    let mut no_storage = storage("pve", "local");
    remove(&mut no_storage, "storage")?;
    let mut slash_storage = storage("pve", "local");
    set(&mut slash_storage, "/storage", r#""a/b""#)?;
    let mut no_node = guest("qemu", "100", "a");
    remove(&mut no_node, "node")?;
    let bad_node = mutated("qemu", "101", "/node", r#""-x""#)?;
    let (items, skipped) = parse(vec![slash, no_storage, slash_storage, no_node, bad_node])?;
    assert!(items.is_empty());
    assert_eq!((skipped.bad_field, skipped.key_lost), (FIVE, THREE));
    assert_eq!(
        skipped.refused_keys,
        vec![key_of(ResourceKind::Qemu, "100"), key_of(ResourceKind::Qemu, "101")]
    );
    Ok(())
}


#[test]
fn a_repeated_identity_keeps_the_first_and_counts_a_duplicate() -> TestResult {
    let (items, skipped) = parse(vec![
        guest("qemu", "100", "first"),
        guest("qemu", "100", "second"),
        guest("lxc", "100", "other"),
    ])?;
    assert_eq!(keys_of(&items), ["100", "100"]);
    assert_eq!(items.first().ok_or("none")?.name.as_deref(), Some("first"));
    assert_eq!(skipped.duplicate, 1);
    Ok(())
}


#[test]
fn a_refused_element_sharing_a_kept_identity_is_a_duplicate_in_either_order() -> TestResult {
    let refused = mutated("qemu", "100", "/name", r#""a\nb""#)?;
    let (after, skipped_after) = parse(vec![guest("qemu", "100", "ok"), refused.clone()])?;
    let (before, skipped_before) = parse(vec![refused, guest("qemu", "100", "ok")])?;
    assert_eq!((keys_of(&after), keys_of(&before)), (vec!["100"], vec!["100"]));
    [skipped_after, skipped_before].iter().for_each(|skipped| {
        assert_eq!((skipped.bad_field, skipped.duplicate), (1, 1));
        assert!(skipped.refused_keys.is_empty());
    });
    Ok(())
}


#[test]
fn the_answer_must_be_json_with_a_data_array() -> TestResult {
    let limits = Limits::default();
    let broken = [
        b"not json".as_slice(),
        b"{}".as_slice(),
        br#"{"data":{"a":1}}"#.as_slice(),
        br#"{"data":null}"#.as_slice(),
        br#"{"data":[1,"#.as_slice(),
    ];
    broken
        .iter()
        .for_each(|input| assert!(matches!(parse_resources(*input, &limits), Err(ParseError::Malformed { .. }))));
    let message = parse_resources(b"{}".as_slice(), &limits).err().ok_or("no error")?.to_string();
    assert!(message.contains("line 1 column"));
    Ok(())
}


#[test]
fn a_non_object_element_is_unparsable() -> TestResult {
    let parsed = parse_resources(br#"{"data":[1,"x",null,[]]}"#.as_slice(), &Limits::default())?;
    assert!(parsed.items.is_empty());
    assert_eq!((parsed.skipped.unparsable, parsed.skipped.key_lost), (OVER_COUNT, OVER_COUNT));
    Ok(())
}


#[test]
fn the_byte_limit_is_exact() -> TestResult {
    let small = Limits {
        max_bytes: SMALL_BYTES,
        ..Limits::default()
    };
    let exact = format!(
        r#"{{"data":[],"x":"{}"}}"#,
        "a".repeat(usize::try_from(SMALL_BYTES)? - r#"{"data":[],"x":""}"#.len())
    );
    assert_eq!(exact.len(), usize::try_from(SMALL_BYTES)?);
    assert!(parse_resources(exact.as_bytes(), &small)?.items.is_empty());
    let over = format!("{exact} ");
    assert!(matches!(
        parse_resources(over.as_bytes(), &small),
        Err(ParseError::TooLarge { max: SMALL_BYTES })
    ));
    Ok(())
}


#[test]
fn a_failing_reader_is_a_read_error() -> TestResult {
    let error = parse_resources(FailingReader, &Limits::default()).err().ok_or("no error")?;
    assert!(matches!(error, ParseError::Read(_)));
    assert!(error.to_string().contains("cannot read"));
    Ok(())
}


#[test]
fn the_item_count_is_refused_above_the_limit_and_accepted_at_it() -> TestResult {
    let limits = Limits {
        max_items: SMALL_ITEMS,
        ..Limits::default()
    };
    let at_limit = (VMID_BASE..VMID_BASE + u64::try_from(SMALL_ITEMS)?)
        .map(|vmid| guest("qemu", &vmid.to_string(), "a"))
        .collect::<Vec<_>>();
    assert_eq!(parse_resources(data(at_limit.clone()).as_slice(), &limits)?.items.len(), SMALL_ITEMS);
    let over = [at_limit, vec![guest("qemu", "200", "a")]].concat();
    assert!(matches!(
        parse_resources(data(over).as_slice(), &limits),
        Err(ParseError::TooManyItems {
            count: OVER_COUNT,
            max: SMALL_ITEMS
        })
    ));
    Ok(())
}


#[test]
fn the_text_cap_applies_to_names() -> TestResult {
    let limits = Limits {
        max_text_bytes: TEXT_CAP,
        ..Limits::default()
    };
    let parsed = parse_resources(
        data(vec![guest("qemu", "100", "12345678"), guest("qemu", "101", "123456789")]).as_slice(),
        &limits,
    )?;
    assert_eq!(keys_of(&parsed.items), ["100"]);
    assert_eq!(parsed.skipped.bad_field, 1);
    Ok(())
}


#[test]
fn a_deeply_nested_document_never_overflows_the_stack() -> TestResult {
    let nested = format!("{}{}", "[".repeat(NEST_DEPTH), "]".repeat(NEST_DEPTH));
    let limits = Limits::default();
    let at_root = format!(r#"{{"data":{nested}}}"#);
    let skipped = parse_resources(at_root.as_bytes(), &limits)?.skipped;
    assert_eq!((skipped.unparsable, skipped.key_lost), (1, 1));
    let in_element = format!(r#"{{"data":[{{"type":"qemu","vmid":100,"node":"pve","x":{nested}}}]}}"#);
    assert_eq!(parse_resources(in_element.as_bytes(), &limits)?.items.len(), 1);
    let in_array = format!(r#"{{"data":[{{"type":"qemu","vmid":100,"node":"pve"}},{nested}]}}"#);
    let parsed = parse_resources(in_array.as_bytes(), &limits)?;
    assert_eq!((parsed.items.len(), parsed.skipped.unparsable), (1, 1));
    Ok(())
}
