mod common;


use common::types::TestResult;
use core_config::error::ConfigError;
use network_devices::devices::{MAX_DEVICES, MAX_DEVICES_PER_FILE};
use network_devices::error::DeviceError;
use network_devices::load::{load_devices, MAX_FILE_ENTRIES};
use network_devices::model::SnmpVersion;
use network_devices::plan::polling_plan;
use std::fs;
use std::path::Path;


const SAMPLE: &str = "tests/fixtures/sample";


const TWO_DEVICES: usize = 2;


const OCTET: usize = 256;


const SQUARE: usize = 65_536;


fn write_file(directory: &Path, name: &str, text: &str) -> TestResult {
    fs::write(directory.join(name), text)?;
    Ok(())
}


fn one_device(name: &str, tenant: &str, address: &str) -> String {
    format!("devices:\n  - {{name: {name}, tenant: {tenant}, kind: switch, addresses: [\"{address}\"], stale_after_seconds: 900}}\n")
}


fn bulk_file(first: usize, count: usize) -> String {
    let lines: Vec<String> = (first..first + count)
        .map(|i| {
            format!(
                "  - {{name: d{i}, tenant: acme, kind: switch, addresses: [\"10.{}.{}.{}\"], stale_after_seconds: 900}}\n",
                i / SQUARE,
                (i / OCTET) % OCTET,
                i % OCTET
            )
        })
        .collect();
    format!("devices:\n{}", lines.concat())
}


#[test]
fn the_sample_directory_loads_with_its_warning_and_plan() -> TestResult {
    let loaded = load_devices(Path::new(SAMPLE))?;
    let names: Vec<&str> = loaded.devices.iter().map(|device| device.name.as_str()).collect();
    assert_eq!(names, vec!["lobby-printer", "core-sw1", "edge-fw1"]);
    assert_eq!(loaded.warnings.len(), 1);
    let warning = loaded.warnings.first().ok_or("no warning")?;
    assert_eq!((warning.device.as_str(), warning.version), ("lobby-printer", SnmpVersion::V2c));
    let plan = polling_plan(&loaded.devices);
    let planned: Vec<&str> = plan.iter().map(|entry| entry.name.as_str()).collect();
    assert_eq!(planned, vec!["core-sw1", "lobby-printer"]);
    Ok(())
}


#[test]
fn a_name_or_address_repeated_across_files_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    write_file(directory.path(), "a.yaml", &one_device("sw", "acme", "192.0.2.1"))?;
    write_file(directory.path(), "b.yml", &one_device("other", "acme", "192.0.2.1"))?;
    let address_clash = load_devices(directory.path());
    assert!(matches!(address_clash, Err(DeviceError::DuplicateAddress { .. })), "{address_clash:?}");
    write_file(directory.path(), "b.yml", &one_device("sw", "acme", "192.0.2.2"))?;
    let name_clash = load_devices(directory.path());
    assert!(matches!(name_clash, Err(DeviceError::DuplicateName { .. })), "{name_clash:?}");
    write_file(directory.path(), "b.yml", &one_device("sw", "globex", "192.0.2.1"))?;
    assert_eq!(load_devices(directory.path())?.devices.len(), TWO_DEVICES);
    Ok(())
}


#[test]
fn other_extensions_are_ignored() -> TestResult {
    let directory = tempfile::tempdir()?;
    write_file(directory.path(), "a.yaml", &one_device("sw", "acme", "192.0.2.1"))?;
    write_file(directory.path(), "notes.txt", "not: [yaml")?;
    write_file(directory.path(), "noextension", "not: [yaml")?;
    assert_eq!(load_devices(directory.path())?.devices.len(), 1);
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_symlink_is_refused_without_reading_its_target() -> TestResult {
    let directory = tempfile::tempdir()?;
    let target = tempfile::tempdir()?;
    write_file(target.path(), "real.yaml", &one_device("sw", "acme", "192.0.2.1"))?;
    std::os::unix::fs::symlink(target.path().join("real.yaml"), directory.path().join("link.yaml"))?;
    let refused = load_devices(directory.path());
    assert!(matches!(refused, Err(DeviceError::Config(ConfigError::Io { .. }))), "{refused:?}");
    Ok(())
}


#[test]
fn a_directory_named_like_a_device_file_is_refused() -> TestResult {
    let directory = tempfile::tempdir()?;
    fs::create_dir(directory.path().join("dir.yaml"))?;
    let refused = load_devices(directory.path());
    assert!(matches!(refused, Err(DeviceError::NotRegular { .. })), "{refused:?}");
    Ok(())
}


#[test]
fn a_missing_directory_is_an_io_error() -> TestResult {
    let refused = load_devices(Path::new("tests/fixtures/absent"));
    assert!(matches!(refused, Err(DeviceError::Config(ConfigError::Io { .. }))), "{refused:?}");
    Ok(())
}


#[test]
fn too_many_entries_are_refused_before_any_is_read() -> TestResult {
    let directory = tempfile::tempdir()?;
    (0..=MAX_FILE_ENTRIES).try_for_each(|i| write_file(directory.path(), &format!("f{i}.txt"), ""))?;
    let refused = load_devices(directory.path());
    assert!(matches!(refused, Err(DeviceError::TooManyEntries { .. })), "{refused:?}");
    Ok(())
}


#[test]
fn the_device_count_is_capped_across_files() -> TestResult {
    let directory = tempfile::tempdir()?;
    let files = MAX_DEVICES / MAX_DEVICES_PER_FILE;
    (0..files).try_for_each(|i| {
        write_file(
            directory.path(),
            &format!("f{i}.yaml"),
            &bulk_file(i * MAX_DEVICES_PER_FILE, MAX_DEVICES_PER_FILE),
        )
    })?;
    assert_eq!(load_devices(directory.path())?.devices.len(), MAX_DEVICES);
    write_file(directory.path(), "extra.yaml", &bulk_file(MAX_DEVICES, 1))?;
    let refused = load_devices(directory.path());
    assert!(matches!(refused, Err(DeviceError::TooManyDevicesInAll { .. })), "{refused:?}");
    Ok(())
}
