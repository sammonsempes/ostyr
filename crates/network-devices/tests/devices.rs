mod common;


use common::types::TestResult;
use core_config::error::ConfigError;
use network_devices::devices::{
    parse_device_file, validate_device, MAX_ADDRESSES, MAX_DEVICES_PER_FILE, MAX_FILE_BYTES, MAX_FLOW_RECORDS_PER_SECOND, MAX_NAME_BYTES,
    MAX_REFERENCE_BYTES, MAX_STALE_SECONDS, MAX_TRAPS_PER_MINUTE,
};
use network_devices::error::DeviceError;
use network_devices::model::{LoadResult, SnmpVersion, Volumes, Warning};
use network_devices::plan::{declared_sources, polling_plan};
use std::error::Error;
use std::io::{self, Read};
use std::net::IpAddr;


const FILE: &str = "site.yaml";


const BASE: &str = "devices:
  - name: core-sw1
    tenant: acme
    kind: switch
    addresses: [192.0.2.10, \"2001:db8::1\"]
    agent_managed: false
    stale_after_seconds: 900
    volumes:
      max_traps_per_minute: 600
      max_flow_records_per_second: 5000
    snmp:
      polling: true
      version: v3
      security_level: auth_priv
      auth_protocol: sha256
      priv_protocol: aes128
      credentials: sites/acme/core-sw1.snmp
";


const AUTH_LINE: &str = "      auth_protocol: sha256\n";


const PRIV_LINE: &str = "      priv_protocol: aes128\n";


const SECURITY_LINE: &str = "      security_level: auth_priv\n";


const SECOND_INDEX: usize = 1;


const BASE_TRAPS: u32 = 600;


const BASE_FLOWS: u32 = 5000;


pub struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected failure"))
    }
}


fn parse(text: &str) -> Result<LoadResult, DeviceError> {
    parse_device_file(&mut text.as_bytes(), FILE)
}


fn changed(from: &str, to: &str) -> String {
    assert!(BASE.contains(from), "base lacks {from:?}");
    BASE.replacen(from, to, 1)
}


fn refused_field(text: &str) -> Result<&'static str, Box<dyn Error>> {
    match parse(text) {
        Err(DeviceError::Invalid { field, index: 0, .. }) => Ok(field),
        other => Err(format!("expected a refused field, got {other:?}").into()),
    }
}


fn block(name: &str, tenant: &str, addresses: &[&str]) -> String {
    let quoted: Vec<String> = addresses.iter().map(|address| format!("\"{address}\"")).collect();
    format!(
        "  - name: {name}\n    tenant: {tenant}\n    kind: switch\n    addresses: [{}]\n    stale_after_seconds: 900\n",
        quoted.join(", ")
    )
}


fn file_of(blocks: &[String]) -> String {
    format!("devices:\n{}", blocks.concat())
}


#[test]
fn the_base_file_is_valid() -> TestResult {
    let loaded = parse(BASE)?;
    assert_eq!(loaded.devices.len(), 1);
    assert!(loaded.warnings.is_empty());
    let device = loaded.devices.first().ok_or("no device")?;
    assert_eq!(
        device.volumes,
        Volumes {
            max_traps_per_minute: BASE_TRAPS,
            max_flow_records_per_second: BASE_FLOWS
        }
    );
    assert_eq!(validate_device(device), Ok(()));
    Ok(())
}


#[test]
fn defaults_apply_to_a_minimal_push_only_device() -> TestResult {
    let loaded = parse(&file_of(&[block("fw", "acme", &["192.0.2.1"])]))?;
    let device = loaded.devices.first().ok_or("no device")?;
    assert_eq!(device.volumes, Volumes::default());
    assert!(!device.agent_managed);
    assert!(device.snmp.is_none());
    Ok(())
}


#[test]
fn each_rule_refuses_an_input_valid_except_for_it() -> TestResult {
    let long_name = "a".repeat(MAX_NAME_BYTES + 1);
    let long_reference = "a".repeat(MAX_REFERENCE_BYTES + 1);
    let many_addresses = (0..=MAX_ADDRESSES).map(|i| format!("192.0.2.{}", i + 1)).collect::<Vec<_>>().join(", ");
    let over_traps = (MAX_TRAPS_PER_MINUTE + 1).to_string();
    let over_flows = (MAX_FLOW_RECORDS_PER_SECOND + 1).to_string();
    let over_stale = (MAX_STALE_SECONDS + 1).to_string();
    let cases: Vec<(String, &str)> = vec![
        (changed("name: core-sw1", "name: -bad"), "name"),
        (changed("name: core-sw1", "name: \"a\\u202Eb\""), "name"),
        (changed("name: core-sw1", "name: \"\""), "name"),
        (changed("name: core-sw1", "name: a/b"), "name"),
        (changed("name: core-sw1", &format!("name: {long_name}")), "name"),
        (changed("tenant: acme", "tenant: -x"), "tenant"),
        (changed("addresses: [192.0.2.10, \"2001:db8::1\"]", "addresses: []"), "addresses"),
        (changed("192.0.2.10, \"2001:db8::1\"", &many_addresses), "addresses"),
        (changed("sites/acme/core-sw1.snmp", "../../etc/shadow"), "snmp.credentials"),
        (changed("sites/acme/core-sw1.snmp", "/etc/shadow"), "snmp.credentials"),
        (changed("sites/acme/core-sw1.snmp", "-x"), "snmp.credentials"),
        (changed("sites/acme/core-sw1.snmp", "\"sites/\\u202Ea\""), "snmp.credentials"),
        (changed("sites/acme/core-sw1.snmp", "sites//a"), "snmp.credentials"),
        (changed("sites/acme/core-sw1.snmp", "sites/a/"), "snmp.credentials"),
        (changed("sites/acme/core-sw1.snmp", &long_reference), "snmp.credentials"),
        (changed("agent_managed: false", "agent_managed: true"), "snmp.polling"),
        (changed("version: v3", "version: v2c"), "snmp.version"),
        (changed("version: v3", "version: v1"), "snmp.version"),
        (changed("security_level: auth_priv", "security_level: auth_no_priv"), "snmp.v3"),
        (changed("security_level: auth_priv", "security_level: no_auth_no_priv"), "snmp.v3"),
        (changed(SECURITY_LINE, ""), "snmp.v3"),
        (changed(AUTH_LINE, ""), "snmp.v3"),
        (changed(PRIV_LINE, ""), "snmp.v3"),
        (
            changed("max_traps_per_minute: 600", "max_traps_per_minute: 0"),
            "volumes.max_traps_per_minute",
        ),
        (
            changed("max_traps_per_minute: 600", &format!("max_traps_per_minute: {over_traps}")),
            "volumes.max_traps_per_minute",
        ),
        (
            changed("max_flow_records_per_second: 5000", "max_flow_records_per_second: 0"),
            "volumes.max_flow_records_per_second",
        ),
        (
            changed("max_flow_records_per_second: 5000", &format!("max_flow_records_per_second: {over_flows}")),
            "volumes.max_flow_records_per_second",
        ),
        (changed("stale_after_seconds: 900", "stale_after_seconds: 0"), "stale_after_seconds"),
        (
            changed("stale_after_seconds: 900", &format!("stale_after_seconds: {over_stale}")),
            "stale_after_seconds",
        ),
    ];
    cases.iter().try_for_each(|(text, field)| {
        let found = refused_field(text)?;
        (found == *field)
            .then_some(())
            .ok_or_else(|| format!("expected {field}, got {found}").into())
    })
}


#[test]
fn a_polled_device_without_an_agent_flag_clash_is_valid_when_polling_is_off() -> TestResult {
    let text = changed("agent_managed: false", "agent_managed: true").replacen("polling: true", "polling: false", 1);
    assert_eq!(parse(&text)?.devices.len(), 1);
    Ok(())
}


#[test]
fn weak_algorithms_and_unknown_values_are_refused_at_parse() -> TestResult {
    let cases = [
        changed("auth_protocol: sha256", "auth_protocol: md5"),
        changed("auth_protocol: sha256", "auth_protocol: sha1"),
        changed("priv_protocol: aes128", "priv_protocol: des"),
        changed("kind: switch", "kind: toaster"),
        changed("version: v3", "version: v4"),
        changed("addresses: [192.0.2.10", "addresses: [192.0.2.300"),
        changed("stale_after_seconds: 900", "stale_after_seconds: 900\n    extra: 1"),
    ];
    cases.iter().try_for_each(|text| match parse(text) {
        Err(DeviceError::Config(ConfigError::Parse { .. })) => Ok(()),
        other => Err(format!("expected a parse error, got {other:?}").into()),
    })
}


#[test]
fn an_insecure_version_is_accepted_for_a_named_device_with_a_warning() -> TestResult {
    let cases = [("v2c", SnmpVersion::V2c), ("v1", SnmpVersion::V1)];
    cases.iter().try_for_each(|(text, version)| {
        let loaded = parse(&changed("version: v3", &format!("version: {text}\n      accept_insecure: true")))?;
        let expected = Warning {
            tenant: "acme".to_owned(),
            device: "core-sw1".to_owned(),
            version: *version,
        };
        assert_eq!(loaded.warnings, vec![expected]);
        assert!(loaded.warnings.first().ok_or("no warning")?.to_string().contains("insecure SNMP"));
        Ok(())
    })
}


#[test]
fn a_device_with_snmp_off_has_no_warning_and_is_not_planned() -> TestResult {
    let loaded = parse(&changed("polling: true", "polling: false"))?;
    assert!(loaded.warnings.is_empty());
    assert!(polling_plan(&loaded.devices).is_empty());
    Ok(())
}


#[test]
fn a_name_may_repeat_across_tenants_but_not_inside_one() -> TestResult {
    assert!(parse(&file_of(&[block("sw", "acme", &["192.0.2.1"]), block("sw", "globex", &["192.0.2.2"])])).is_ok());
    match parse(&file_of(&[block("sw", "acme", &["192.0.2.1"]), block("sw", "acme", &["192.0.2.2"])])) {
        Err(DeviceError::DuplicateName { index, .. }) if index == SECOND_INDEX => Ok(()),
        other => Err(format!("expected DuplicateName, got {other:?}").into()),
    }
}


#[test]
fn an_address_is_claimed_once_per_tenant_by_source_key() -> TestResult {
    assert!(parse(&file_of(&[block("a", "acme", &["192.0.2.1"]), block("b", "globex", &["192.0.2.1"])])).is_ok());
    assert!(parse(&file_of(&[block("a", "acme", &["2001:db8::1", "2001:db8::2"])])).is_ok());
    let clashes = [
        [block("a", "acme", &["192.0.2.1"]), block("b", "acme", &["192.0.2.1"])],
        [block("a", "acme", &["2001:db8::1"]), block("b", "acme", &["2001:db8::2"])],
        [block("a", "acme", &["192.0.2.1"]), block("b", "acme", &["::ffff:192.0.2.1"])],
    ];
    clashes.iter().try_for_each(|blocks| match parse(&file_of(blocks)) {
        Err(DeviceError::DuplicateAddress { index, .. }) if index == SECOND_INDEX => Ok(()),
        other => Err(format!("expected DuplicateAddress, got {other:?}").into()),
    })
}


#[test]
fn too_many_devices_are_refused_after_the_size_cap_bounds_them() -> TestResult {
    let line = "  - {name: d, tenant: acme, kind: switch, addresses: [192.0.2.1], stale_after_seconds: 900}\n";
    let text = format!("devices:\n{}", line.repeat(MAX_DEVICES_PER_FILE + 1));
    assert!(text.len() as u64 <= MAX_FILE_BYTES);
    match parse(&text) {
        Err(DeviceError::TooManyDevices { count, .. }) if count == MAX_DEVICES_PER_FILE + 1 => Ok(()),
        other => Err(format!("expected TooManyDevices, got {other:?}").into()),
    }
}


#[test]
fn an_oversized_or_unreadable_file_is_refused() -> TestResult {
    let oversized = parse_device_file(&mut io::repeat(b' '), FILE);
    assert!(
        matches!(oversized, Err(DeviceError::Config(ConfigError::TooLarge { .. }))),
        "{oversized:?}"
    );
    let unreadable = parse_device_file(&mut FailingReader, FILE);
    assert!(matches!(unreadable, Err(DeviceError::Config(ConfigError::Io { .. }))), "{unreadable:?}");
    Ok(())
}


#[test]
fn the_credentials_reference_is_never_opened() -> TestResult {
    let loaded = parse(&changed("sites/acme/core-sw1.snmp", "no/such/dir/never-read.snmp"))?;
    assert_eq!(loaded.devices.len(), 1);
    Ok(())
}


#[test]
fn a_secret_file_content_never_reaches_debug_or_display() -> TestResult {
    let directory = tempfile::tempdir()?;
    let marker = "MARKER-SECRET-VALUE";
    std::fs::create_dir_all(directory.path().join("sites/acme"))?;
    std::fs::write(directory.path().join("sites/acme/core-sw1.snmp"), marker)?;
    let loaded = parse(BASE)?;
    assert!(!format!("{loaded:?}").contains(marker));
    let refusals = [
        changed("sites/acme/core-sw1.snmp", "../sites/acme/core-sw1.snmp"),
        changed("auth_protocol: sha256", "auth_protocol: md5"),
    ];
    refusals.iter().try_for_each(|text| {
        let error = parse(text).err().ok_or("expected a refusal")?;
        assert!(!format!("{error:?} {error}").contains(marker));
        Ok::<(), Box<dyn Error>>(())
    })?;
    let invalid = parse(&changed("sites/acme/core-sw1.snmp", "-x")).err().ok_or("expected a refusal")?;
    assert_eq!(invalid.to_string(), "\"site.yaml\": device #0: invalid `snmp.credentials`");
    Ok(())
}


#[test]
fn the_plan_lists_polled_devices_sorted_by_tenant_and_name() -> TestResult {
    let polled = |name: &str, tenant: &str, address: &str| {
        let text = changed("name: core-sw1", &format!("name: {name}"))
            .replacen("tenant: acme", &format!("tenant: {tenant}"), 1)
            .replacen("192.0.2.10, \"2001:db8::1\"", address, 1);
        parse(&text).map(|loaded| loaded.devices)
    };
    let mut devices = polled("zeta", "acme", "192.0.2.1")?;
    devices.extend(polled("alpha", "globex", "192.0.2.2")?);
    devices.extend(polled("beta", "acme", "192.0.2.3")?);
    devices.extend(parse(&file_of(&[block("push", "acme", &["192.0.2.4"])]))?.devices);
    let plan = polling_plan(&devices);
    let order: Vec<(&str, &str)> = plan.iter().map(|entry| (entry.tenant.as_str(), entry.name.as_str())).collect();
    assert_eq!(order, vec![("acme", "beta"), ("acme", "zeta"), ("globex", "alpha")]);
    let first = plan.first().ok_or("empty plan")?;
    assert_eq!(first.version, SnmpVersion::V3);
    assert_eq!(first.credentials, "sites/acme/core-sw1.snmp");
    assert_eq!(first.addresses.len(), 1);
    Ok(())
}


#[test]
fn the_plan_never_holds_a_device_that_runs_an_agent() -> TestResult {
    let mut devices = parse(BASE)?.devices;
    devices.iter_mut().for_each(|device| device.agent_managed = true);
    assert!(polling_plan(&devices).is_empty());
    Ok(())
}


#[test]
fn declared_sources_are_the_tenant_addresses_by_source_key() -> TestResult {
    let mut devices = parse(BASE)?.devices;
    devices.extend(parse(&file_of(&[block("push", "acme", &["192.0.2.4", "2001:db8::9"])]))?.devices);
    devices.extend(parse(&file_of(&[block("other", "globex", &["192.0.2.99"])]))?.devices);
    let sources = declared_sources(&devices, "acme");
    let expected: Vec<IpAddr> = vec!["192.0.2.4".parse()?, "192.0.2.10".parse()?, "2001:db8::".parse()?];
    assert_eq!(sources.into_iter().collect::<Vec<_>>(), expected);
    assert!(declared_sources(&devices, "nobody").is_empty());
    Ok(())
}
