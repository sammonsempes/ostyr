#[path = "common/reader.rs"]
mod reader;
#[path = "common/types.rs"]
mod types;


use reader::FailingReader;
use types::TestResult;
use virt_inventory::cmdb_sync::{asset_kind, cloud_id, kind_text, observation_of, observations, source_for, source_of};
use virt_inventory::error::ParseError;
use virt_inventory::limits::Limits;
use virt_inventory::model::{ItemKey, Parsed, Resource, ResourceKind};
use virt_inventory::proxmox::{identity_in, identity_of, status_values};
use virt_inventory::vsphere::{convert_item, list_cap, parse_hosts, parse_vms, valid_id, HOST_LIST_CAP, VM_LIST_CAP};


const VM_REFERENCE_8: &str = r#"[{"vm":"vm-12","name":"web 01","power_state":"POWERED_ON","cpu_count":2,"memory_size_MiB":4096},
{"vm":"vm-13","name":"db","power_state":"POWERED_OFF","cpu_count":4,"memory_size_MiB":8192}]"#;


const VM_REFERENCE_9: &str = r#"[{"vm":"vm-12","name":"web","power_state":"SUSPENDED","cpu_count":2,"memory_size_mib":4096}]"#;


const HOST_REFERENCE: &str = r#"[{"host":"host-9","name":"esx1","connection_state":"CONNECTED","power_state":"POWERED_ON"},
{"host":"host-10","name":"esx2","connection_state":"NOT_RESPONDING","power_state":"STANDBY"}]"#;


const MEBIBYTES_AT_LIMIT: u64 = 8_589_934_592;


const GIB_MEBIBYTES: u64 = 1_024;


const TWO_POW_53: u64 = 9_007_199_254_740_992;


const TWO_POW_60: u64 = 1_152_921_504_606_846_976;


const OVER_CPU: u64 = 65_537;


const ID_LIMIT: usize = 32;


const FOUR: usize = 4;


const SMALL_BYTES: u64 = 16;


const SMALL_ITEMS: usize = 1;


const THREE: usize = 3;


const TWO: usize = 2;


const TWO_CPUS: u64 = 2;


const VM_MEBIBYTES: u64 = 4_096;


const MIB_BYTES: u64 = 1_048_576;


const CPU_LIMIT: u64 = 65_536;


const VMID: u64 = 100;


fn vms(text: &str) -> Result<Parsed, ParseError> {
    parse_vms(text.as_bytes(), &Limits::default())
}


fn one_vm(fields: &str) -> Result<Parsed, ParseError> {
    vms(&format!("[{{{fields}}}]"))
}


fn array_of(unit: &str, count: usize) -> String {
    format!("[{}]", vec![unit; count].join(","))
}


fn vm_item(index: usize) -> String {
    format!(r#"{{"vm":"vm-{index}","name":"n","power_state":"POWERED_ON","cpu_count":1,"memory_size_MiB":1}}"#)
}


fn many_vms(count: usize) -> String {
    format!("[{}]", (0..count).map(vm_item).collect::<Vec<_>>().join(","))
}


#[test]
fn the_8_0_reference_shape_parses_into_vm_resources() -> TestResult {
    let parsed = vms(VM_REFERENCE_8)?;
    let first = parsed.items.first().ok_or("no first")?;
    assert_eq!(first.kind, ResourceKind::VsphereVm);
    assert_eq!(first.key, "vm-12");
    assert_eq!(first.name.as_deref(), Some("web 01"));
    assert_eq!(first.status.as_deref(), Some("POWERED_ON"));
    assert_eq!((first.max_cpu, first.max_mem), (Some(TWO_CPUS), Some(VM_MEBIBYTES * MIB_BYTES)));
    assert_eq!((first.node.as_str(), first.template, first.max_disk), ("", false, None));
    assert_eq!(parsed.items.len(), TWO);
    assert_eq!(parsed.skipped, Default::default());
    Ok(())
}


#[test]
fn the_9_0_lowercase_memory_spelling_is_read_too() -> TestResult {
    let parsed = vms(VM_REFERENCE_9)?;
    let first = parsed.items.first().ok_or("no first")?;
    assert_eq!(
        (first.max_mem, first.status.as_deref()),
        (Some(VM_MEBIBYTES * MIB_BYTES), Some("SUSPENDED"))
    );
    let both = one_vm(r#""vm":"vm-1","memory_size_MiB":1,"memory_size_mib":2"#)?;
    assert_eq!((both.items.len(), both.skipped.unparsable, both.skipped.refused_keys.len()), (0, 1, 1));
    Ok(())
}


#[test]
fn the_host_reference_shape_parses_into_host_resources() -> TestResult {
    let parsed = parse_hosts(HOST_REFERENCE.as_bytes(), &Limits::default())?;
    let keys = parsed
        .items
        .iter()
        .map(|item| (item.kind, item.key.as_str(), item.status.as_deref()))
        .collect::<Vec<_>>();
    assert_eq!(
        keys,
        vec![
            (ResourceKind::VsphereHost, "host-9", Some("POWERED_ON")),
            (ResourceKind::VsphereHost, "host-10", Some("STANDBY"))
        ]
    );
    assert!(parsed
        .items
        .iter()
        .all(|item| item.max_cpu.is_none() && item.max_mem.is_none() && item.node.is_empty()));
    assert_eq!(parsed.skipped, Default::default());
    Ok(())
}


#[test]
fn a_host_never_reads_the_vm_fields_and_a_vm_never_the_host_id() -> TestResult {
    let host = parse_hosts(
        r#"[{"host":"host-1","cpu_count":[1],"memory_size_MiB":"x","vm":"vm-1"}]"#.as_bytes(),
        &Limits::default(),
    )?;
    assert_eq!((host.items.len(), host.skipped.bad_field), (1, 0));
    let vm = one_vm(r#""host":"host-1""#)?;
    assert_eq!((vm.items.len(), vm.skipped.bad_field, vm.skipped.key_lost), (0, 1, 1));
    let wrong = parse_hosts(r#"[{"host":"vm-1"}]"#.as_bytes(), &Limits::default())?;
    assert_eq!((wrong.items.len(), wrong.skipped.bad_field), (0, 1));
    Ok(())
}


#[test]
fn the_id_is_an_ascii_allowlist_and_a_bad_one_is_skipped_alone() -> TestResult {
    let long = format!("vm-{}", "1".repeat(ID_LIMIT));
    let exact = format!("vm-{}", "1".repeat(ID_LIMIT - FOUR + 1));
    let items = [
        r#"{"vm":"vm-12/../x"}"#,
        r#"{"vm":"vm-"}"#,
        r#"{"vm":"vm-1a"}"#,
        r#"{"vm":"VM-1"}"#,
        r#"{"vm":"vm-١"}"#,
        r#"{"vm":"vm-1 "}"#,
        r#"{"vm":5}"#,
        r#"{"vm":null}"#,
        r#"{"name":"x"}"#,
        r#"{"vm":"vm-7"}"#,
    ];
    let parsed = vms(&format!("[{}]", items.join(",")))?;
    assert_eq!(parsed.items.iter().map(|item| item.key.as_str()).collect::<Vec<_>>(), vec!["vm-7"]);
    assert_eq!(parsed.skipped.bad_field, items.len() - 1);
    let long_parsed = one_vm(&format!(r#""vm":"{long}""#))?;
    assert_eq!((long_parsed.items.len(), long_parsed.skipped.bad_field), (0, 1));
    let exact_parsed = one_vm(&format!(r#""vm":"{exact}""#))?;
    assert_eq!(exact_parsed.items.len(), 1);
    assert!(valid_id(ResourceKind::VsphereHost, "host-0"));
    assert!(!valid_id(ResourceKind::VsphereHost, "vm-0"));
    Ok(())
}


#[test]
fn a_refused_element_with_a_readable_id_keeps_its_key() -> TestResult {
    let parsed = vms(r#"[{"vm":"vm-5","cpu_count":"two"},{"vm":"vm-6","name":[[1]]},{"vm":"vm-6x","name":[]},{"vm":"vm-8","vm":"vm-8"}]"#)?;
    assert_eq!(parsed.skipped.bad_field, THREE);
    assert_eq!(parsed.skipped.unparsable, 1);
    assert_eq!(
        parsed.skipped.refused_keys,
        vec![
            ItemKey {
                kind: ResourceKind::VsphereVm,
                key: "vm-5".to_owned()
            },
            ItemKey {
                kind: ResourceKind::VsphereVm,
                key: "vm-6".to_owned()
            }
        ]
    );
    assert_eq!(parsed.skipped.key_lost, TWO);
    Ok(())
}


#[test]
fn a_nested_array_in_an_element_field_refuses_that_element_only() -> TestResult {
    let parsed = vms(&format!(r#"[{},{{"vm":"vm-2","cpu_count":[[[1]]]}},{}]"#, vm_item(1), vm_item(THREE)))?;
    assert_eq!(parsed.items.len(), TWO);
    assert_eq!((parsed.skipped.bad_field, parsed.skipped.unparsable), (1, 0));
    Ok(())
}


#[test]
fn a_duplicate_id_keeps_the_first_and_drops_a_shadowed_refusal() -> TestResult {
    let parsed = vms(r#"[{"vm":"vm-1","name":"first"},{"vm":"vm-1","name":"second"},{"vm":"vm-1","cpu_count":"x"}]"#)?;
    assert_eq!(parsed.items.len(), 1);
    assert_eq!(parsed.items.first().and_then(|item| item.name.as_deref()), Some("first"));
    assert_eq!((parsed.skipped.duplicate, parsed.skipped.bad_field), (TWO, 1));
    assert!(parsed.skipped.refused_keys.is_empty());
    Ok(())
}


#[test]
fn a_name_with_a_bidi_override_or_an_invisible_letter_is_dropped_and_the_vm_kept() -> TestResult {
    let long = "a".repeat(Limits::default().max_text_bytes + 1);
    let names = ["a\u{202e}b", "a\u{3164}b", "caf\u{e9}", "", " x", "x ", "a  b", "a\u{1b}b", long.as_str()];
    names.iter().try_for_each(|name| -> TestResult {
        let parsed = one_vm(&format!(r#""vm":"vm-1","name":{}"#, serde_json::to_string(name)?))?;
        let item = parsed.items.first().ok_or("item dropped")?;
        assert_eq!((item.name.clone(), parsed.skipped.name_dropped), (None, 1), "name {name:?}");
        Ok(())
    })?;
    let missing = one_vm(r#""vm":"vm-1""#)?;
    assert_eq!((missing.items.len(), missing.skipped.name_dropped), (1, 0));
    let wrong = one_vm(r#""vm":"vm-1","name":3"#)?;
    assert_eq!((wrong.items.len(), wrong.skipped.bad_field), (0, 1));
    Ok(())
}


#[test]
fn a_power_state_outside_its_documented_set_is_absent_and_counted() -> TestResult {
    ["powered_on", "POWERED_ON\u{200b}", "STANDBY", "", "X"]
        .iter()
        .try_for_each(|state| -> TestResult {
            let parsed = one_vm(&format!(r#""vm":"vm-1","power_state":"{state}""#))?;
            let item = parsed.items.first().ok_or("item dropped")?;
            assert_eq!((item.status.clone(), parsed.skipped.field_dropped), (None, 1), "state {state:?}");
            Ok(())
        })?;
    let host = parse_hosts(r#"[{"host":"host-1","power_state":"SUSPENDED"}]"#.as_bytes(), &Limits::default())?;
    assert_eq!((host.items.len(), host.skipped.field_dropped), (1, 1));
    let missing = one_vm(r#""vm":"vm-1","power_state":null"#)?;
    assert_eq!((missing.items.len(), missing.skipped.field_dropped), (1, 0));
    let wrong = one_vm(r#""vm":"vm-1","power_state":["POWERED_ON"]"#)?;
    assert_eq!((wrong.items.len(), wrong.skipped.bad_field), (0, 1));
    Ok(())
}


#[test]
fn cpu_count_is_bounded_and_wrong_types_refuse_the_element() -> TestResult {
    let at = one_vm(r#""vm":"vm-1","cpu_count":65536"#)?;
    assert_eq!(at.items.first().and_then(|item| item.max_cpu), Some(CPU_LIMIT));
    let over = one_vm(&format!(r#""vm":"vm-1","cpu_count":{OVER_CPU}"#))?;
    assert_eq!((over.items.first().map(|item| item.max_cpu), over.skipped.field_dropped), (Some(None), 1));
    let absent = one_vm(r#""vm":"vm-1","cpu_count":null"#)?;
    assert_eq!((absent.items.len(), absent.skipped.field_dropped), (1, 0));
    ["-1", "1.5", r#""2""#, "true", "{}", "1e30"].iter().try_for_each(|value| -> TestResult {
        let parsed = one_vm(&format!(r#""vm":"vm-1","cpu_count":{value}"#))?;
        assert_eq!((parsed.items.len(), parsed.skipped.bad_field), (0, 1), "value {value}");
        Ok(())
    })
}


#[test]
fn memory_is_multiplied_with_checked_arithmetic_and_never_wraps() -> TestResult {
    let at = one_vm(&format!(r#""vm":"vm-1","memory_size_MiB":{MEBIBYTES_AT_LIMIT}"#))?;
    assert_eq!(at.items.first().and_then(|item| item.max_mem), Some(TWO_POW_53));
    let one_over = one_vm(&format!(r#""vm":"vm-1","memory_size_MiB":{}"#, MEBIBYTES_AT_LIMIT + 1))?;
    assert_eq!(
        (one_over.items.first().map(|item| item.max_mem), one_over.skipped.field_dropped),
        (Some(None), 1)
    );
    [TWO_POW_53, TWO_POW_60, u64::MAX].iter().try_for_each(|mebibytes| -> TestResult {
        let parsed = one_vm(&format!(r#""vm":"vm-1","memory_size_MiB":{mebibytes}"#))?;
        assert_eq!(
            (parsed.items.first().map(|item| item.max_mem), parsed.skipped.field_dropped),
            (Some(None), 1),
            "{mebibytes}"
        );
        Ok(())
    })?;
    let gib = one_vm(&format!(r#""vm":"vm-1","memory_size_MiB":{GIB_MEBIBYTES}"#))?;
    assert_eq!(gib.items.first().and_then(|item| item.max_mem), Some(GIB_MEBIBYTES * MIB_BYTES));
    ["-1", "1.5", r#""4096""#, "[1]", "1e30", "18446744073709551616"]
        .iter()
        .try_for_each(|value| -> TestResult {
            let parsed = one_vm(&format!(r#""vm":"vm-1","memory_size_MiB":{value}"#))?;
            assert_eq!((parsed.items.len(), parsed.skipped.bad_field), (0, 1), "value {value}");
            Ok(())
        })
}


#[test]
fn an_unknown_field_is_ignored_and_a_non_object_element_is_unparsable() -> TestResult {
    let parsed = vms(r#"[{"vm":"vm-1","extra":{"a":[1,2]}},5,"x",[],null]"#)?;
    assert_eq!((parsed.items.len(), parsed.skipped.unparsable, parsed.skipped.key_lost), (1, FOUR, FOUR));
    Ok(())
}


#[test]
fn the_list_cap_is_refused_by_the_pre_count_before_any_element_is_built() -> TestResult {
    assert_eq!(
        (list_cap(ResourceKind::VsphereVm), list_cap(ResourceKind::VsphereHost)),
        (VM_LIST_CAP, HOST_LIST_CAP)
    );
    let at = vms(&many_vms(VM_LIST_CAP))?;
    assert_eq!(at.items.len(), VM_LIST_CAP);
    let refused = vms(&many_vms(VM_LIST_CAP + 1));
    assert!(matches!(refused, Err(ParseError::TooManyItems { count, max }) if count == VM_LIST_CAP + 1 && max == VM_LIST_CAP));
    let hosts = array_of(r#"{"host":"host-1"}"#, HOST_LIST_CAP + 1);
    let host_refused = parse_hosts(hosts.as_bytes(), &Limits::default());
    assert!(matches!(host_refused, Err(ParseError::TooManyItems { count, max }) if count == HOST_LIST_CAP + 1 && max == HOST_LIST_CAP));
    let small = Limits {
        max_items: SMALL_ITEMS,
        ..Limits::default()
    };
    assert!(matches!(
        parse_vms(many_vms(TWO).as_bytes(), &small),
        Err(ParseError::TooManyItems { max: 1, .. })
    ));
    Ok(())
}


#[test]
fn a_pre_count_refusal_never_parses_the_elements() -> TestResult {
    let bad_elements = array_of(r#"{"vm":["#, VM_LIST_CAP + 1);
    assert!(matches!(vms(&bad_elements), Err(ParseError::Malformed { .. })));
    let hostile = format!("[{}]", vec!["{}"; VM_LIST_CAP + 1].join(","));
    assert!(matches!(vms(&hostile), Err(ParseError::TooManyItems { .. })));
    Ok(())
}


#[test]
fn a_bad_document_is_refused_with_a_fixed_category() -> TestResult {
    assert!(matches!(vms(r#"{"value":[]}"#), Err(ParseError::Malformed { .. })));
    assert!(matches!(vms("[1,"), Err(ParseError::Malformed { .. })));
    assert!(matches!(vms(""), Err(ParseError::Malformed { .. })));
    let small = Limits {
        max_bytes: SMALL_BYTES,
        ..Limits::default()
    };
    assert!(matches!(
        parse_vms(VM_REFERENCE_8.as_bytes(), &small),
        Err(ParseError::TooLarge { max: SMALL_BYTES })
    ));
    assert!(matches!(parse_hosts(FailingReader, &Limits::default()), Err(ParseError::Read(_))));
    let marker = vms(r#"[{"vm":"vm-1","name":"SECRET-MARKER"}"#).err().ok_or("accepted")?;
    assert!(!format!("{marker} {marker:?}").contains("SECRET-MARKER"));
    Ok(())
}


#[test]
fn an_empty_list_is_an_empty_inventory() -> TestResult {
    let parsed = vms("[]")?;
    assert_eq!((parsed.items.len(), parsed.skipped), (0, Default::default()));
    Ok(())
}


#[test]
fn convert_item_reports_the_dropped_counts() -> TestResult {
    let raw =
        serde_json::value::RawValue::from_string(r#"{"vm":"vm-1","name":"ㅤ","power_state":"x","cpu_count":99999,"memory_size_MiB":1}"#.to_owned())?;
    let done = convert_item(ResourceKind::VsphereVm, &raw, &Limits::default()).map_err(|_| "refused")?;
    assert_eq!((done.name_dropped, done.field_dropped), (1, TWO));
    Ok(())
}


fn proxmox_qemu(key: &str) -> Resource {
    Resource {
        kind: ResourceKind::Qemu,
        key: key.to_owned(),
        name: None,
        node: "pve".to_owned(),
        status: None,
        max_cpu: None,
        max_mem: None,
        max_disk: None,
        template: false,
    }
}


#[test]
fn a_vsphere_vm_and_a_proxmox_guest_with_one_cluster_and_key_have_distinct_identities() -> TestResult {
    let vm = vms(r#"[{"vm":"vm-100"}]"#)?.items.into_iter().next().ok_or("no vm")?;
    let qemu = proxmox_qemu("vm-100");
    let vsphere_id = cloud_id("lab", &vm)?;
    assert_eq!(vsphere_id, "vsphere:lab/vm/vm-100");
    assert_eq!(cloud_id("lab", &qemu)?, "proxmox:lab/qemu/vm-100");
    assert_ne!(vsphere_id, cloud_id("lab", &qemu)?);
    assert_ne!(source_for("lab", vm.kind), source_for("lab", qemu.kind));
    assert_eq!(source_for("lab", qemu.kind), source_of("lab"));
    assert_eq!(source_for("lab", vm.kind), "virt-inventory:vsphere:lab");
    Ok(())
}


#[test]
fn vsphere_items_map_to_cmdb_kinds_and_observations_with_an_empty_node() -> TestResult {
    let vm = vms(VM_REFERENCE_8)?;
    let hosts = parse_hosts(HOST_REFERENCE.as_bytes(), &Limits::default())?;
    let all = vm.items.into_iter().chain(hosts.items).collect::<Vec<_>>();
    let (found, counters) = observations("lab", &all);
    assert_eq!((counters.observed, counters.refused, found.len()), (FOUR, 0, FOUR));
    assert_eq!(kind_text(ResourceKind::VsphereVm), "vm");
    assert_eq!(kind_text(ResourceKind::VsphereHost), "host");
    assert_eq!(asset_kind(ResourceKind::VsphereVm), cmdb::model::AssetKind::VirtualMachine);
    assert_eq!(asset_kind(ResourceKind::VsphereHost), cmdb::model::AssetKind::Server);
    let first = all.first().ok_or("none")?;
    let observation = observation_of("lab", first)?;
    assert_eq!(observation.attributes.get("virt.node").map(String::as_str), Some(""));
    assert_eq!(observation.source, "virt-inventory:vsphere:lab");
    assert!(found.iter().all(|one| one.keys.len() == 1));
    let (none, refused) = observations("bad cluster", &all);
    assert_eq!((none.len(), refused.refused), (0, FOUR));
    Ok(())
}


#[test]
fn proxmox_helpers_know_no_vsphere_identity_and_list_the_power_sets() -> TestResult {
    assert_eq!(identity_of(ResourceKind::VsphereVm, Some(VMID), Some("pve"), None), None);
    assert_eq!(identity_of(ResourceKind::VsphereHost, Some(VMID), Some("pve"), None), None);
    assert_eq!(identity_in(ResourceKind::VsphereVm, r#"{"vm":"vm-1"}"#), None);
    assert_eq!(identity_in(ResourceKind::VsphereHost, r#"{"host":"host-1"}"#), None);
    assert_eq!(status_values(ResourceKind::VsphereVm), ["POWERED_ON", "POWERED_OFF", "SUSPENDED"]);
    assert_eq!(status_values(ResourceKind::VsphereHost), ["POWERED_ON", "POWERED_OFF", "STANDBY"]);
    Ok(())
}
