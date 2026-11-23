#[path = "common/types.rs"]
mod types;


use core_audit::log::{append, genesis_log};
use core_config::reload::{current_config, reload, ReloadContext, ReloadEngine, ReloadOutcome};
use net_topology::limits::{Limits, MAX_HOST_READ_BYTES_CEILING, MAX_HOST_SECONDS_CEILING, MAX_PORT_TIMEOUT_SECONDS};
use net_topology::links::MAX_STALE_AFTER_SECONDS;
use net_topology::settings::{
    limits_of, open_topology, parse_settings, validate_settings, OpenError, Settings, MAX_CAPABILITIES_CEILING, MAX_INTERFACES_CEILING,
    MAX_LINKS_PER_HOST_CEILING, MAX_NEIGHBOURS_CEILING, MAX_TEXT_BYTES_CEILING,
};
use std::fs;
use std::io;
use std::path::Path;
use types::TestResult;


struct Case {
    name: &'static str,
    below: Settings,
    low: Settings,
    high: Settings,
    above: Settings,
}


const STALE_OLD: i64 = 300;


const STALE_NEW: i64 = 900;


fn field_of(settings: &Settings) -> Option<&'static str> {
    validate_settings(settings).err().map(|error| error.field)
}


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "net-topology".to_owned(),
        tenant: "example".to_owned(),
        module: "net-topology".to_owned(),
        target: "net-topology.yaml".to_owned(),
        request_id: "reload".to_owned(),
    }
}


fn open_settings_file(path: &Path) -> Result<ReloadEngine<Settings>, OpenError> {
    let log = genesis_log(io::sink());
    open_topology(path.to_owned(), Box::new(move |entry| append(&log, entry)), context())
}


fn base() -> Settings {
    Settings::default()
}


fn case(name: &'static str, below: Settings, low: Settings, high: Settings, above: Settings) -> Case {
    Case {
        name,
        below,
        low,
        high,
        above,
    }
}


fn cases() -> Vec<Case> {
    vec![
        case(
            "stale_after_seconds",
            Settings {
                stale_after_seconds: 0,
                ..base()
            },
            Settings {
                stale_after_seconds: 1,
                ..base()
            },
            Settings {
                stale_after_seconds: MAX_STALE_AFTER_SECONDS,
                ..base()
            },
            Settings {
                stale_after_seconds: MAX_STALE_AFTER_SECONDS + 1,
                ..base()
            },
        ),
        case(
            "max_bytes",
            Settings { max_bytes: 0, ..base() },
            Settings {
                max_bytes: 1,
                max_port_bytes: 1,
                ..base()
            },
            Settings {
                max_bytes: MAX_HOST_READ_BYTES_CEILING,
                ..base()
            },
            Settings {
                max_bytes: MAX_HOST_READ_BYTES_CEILING + 1,
                ..base()
            },
        ),
        case(
            "max_port_bytes",
            Settings { max_port_bytes: 0, ..base() },
            Settings { max_port_bytes: 1, ..base() },
            Settings {
                max_port_bytes: base().max_bytes,
                ..base()
            },
            Settings {
                max_port_bytes: base().max_bytes + 1,
                ..base()
            },
        ),
        case(
            "max_host_read_bytes",
            Settings {
                max_host_read_bytes: base().max_port_bytes - 1,
                ..base()
            },
            Settings {
                max_host_read_bytes: base().max_port_bytes,
                ..base()
            },
            Settings {
                max_host_read_bytes: MAX_HOST_READ_BYTES_CEILING,
                ..base()
            },
            Settings {
                max_host_read_bytes: MAX_HOST_READ_BYTES_CEILING + 1,
                ..base()
            },
        ),
        case(
            "port_timeout_seconds",
            Settings {
                port_timeout_seconds: 0,
                ..base()
            },
            Settings {
                port_timeout_seconds: 1,
                ..base()
            },
            Settings {
                port_timeout_seconds: MAX_PORT_TIMEOUT_SECONDS,
                ..base()
            },
            Settings {
                port_timeout_seconds: MAX_PORT_TIMEOUT_SECONDS + 1,
                ..base()
            },
        ),
        case(
            "max_host_seconds",
            Settings {
                max_host_seconds: base().port_timeout_seconds - 1,
                ..base()
            },
            Settings {
                max_host_seconds: base().port_timeout_seconds,
                ..base()
            },
            Settings {
                max_host_seconds: MAX_HOST_SECONDS_CEILING,
                ..base()
            },
            Settings {
                max_host_seconds: MAX_HOST_SECONDS_CEILING + 1,
                ..base()
            },
        ),
        case(
            "max_interfaces",
            Settings { max_interfaces: 0, ..base() },
            Settings { max_interfaces: 1, ..base() },
            Settings {
                max_interfaces: MAX_INTERFACES_CEILING,
                ..base()
            },
            Settings {
                max_interfaces: MAX_INTERFACES_CEILING + 1,
                ..base()
            },
        ),
        case(
            "max_neighbours_per_interface",
            Settings {
                max_neighbours_per_interface: 0,
                ..base()
            },
            Settings {
                max_neighbours_per_interface: 1,
                ..base()
            },
            Settings {
                max_neighbours_per_interface: MAX_NEIGHBOURS_CEILING,
                ..base()
            },
            Settings {
                max_neighbours_per_interface: MAX_NEIGHBOURS_CEILING + 1,
                ..base()
            },
        ),
        case(
            "max_capabilities",
            Settings {
                max_capabilities: 0,
                ..base()
            },
            Settings {
                max_capabilities: 1,
                ..base()
            },
            Settings {
                max_capabilities: MAX_CAPABILITIES_CEILING,
                ..base()
            },
            Settings {
                max_capabilities: MAX_CAPABILITIES_CEILING + 1,
                ..base()
            },
        ),
        case(
            "max_text_bytes",
            Settings { max_text_bytes: 0, ..base() },
            Settings { max_text_bytes: 1, ..base() },
            Settings {
                max_text_bytes: MAX_TEXT_BYTES_CEILING,
                ..base()
            },
            Settings {
                max_text_bytes: MAX_TEXT_BYTES_CEILING + 1,
                ..base()
            },
        ),
        case(
            "max_links_per_host",
            Settings {
                max_links_per_host: 0,
                max_links_per_port: 0,
                ..base()
            },
            Settings {
                max_links_per_host: 1,
                max_links_per_port: 1,
                ..base()
            },
            Settings {
                max_links_per_host: MAX_LINKS_PER_HOST_CEILING,
                ..base()
            },
            Settings {
                max_links_per_host: MAX_LINKS_PER_HOST_CEILING + 1,
                ..base()
            },
        ),
        case(
            "max_links_per_port",
            Settings {
                max_links_per_port: 0,
                ..base()
            },
            Settings {
                max_links_per_port: 1,
                ..base()
            },
            Settings {
                max_links_per_port: base().max_links_per_host,
                ..base()
            },
            Settings {
                max_links_per_port: base().max_links_per_host + 1,
                ..base()
            },
        ),
    ]
}


#[test]
fn defaults_match_the_limits_and_validate() -> TestResult {
    let parsed = parse_settings("{}", "t.yaml")?;
    assert_eq!(parsed, base());
    assert_eq!(limits_of(&parsed), Limits::default());
    assert_eq!(field_of(&parsed), None);
    Ok(())
}


#[test]
fn an_unknown_key_or_a_wrong_type_is_refused() -> TestResult {
    assert!(parse_settings("bogus: 1\n", "t.yaml").is_err());
    assert!(parse_settings("max_bytes: -1\n", "t.yaml").is_err());
    assert!(parse_settings("max_bytes: text\n", "t.yaml").is_err());
    Ok(())
}


#[test]
fn every_field_is_checked_at_its_bounds() -> TestResult {
    cases().iter().for_each(|case| {
        assert_eq!(field_of(&case.below), Some(case.name), "{} below", case.name);
        assert_eq!(field_of(&case.low), None, "{} low", case.name);
        assert_eq!(field_of(&case.high), None, "{} high", case.name);
        assert_eq!(field_of(&case.above), Some(case.name), "{} above", case.name);
    });
    Ok(())
}


#[test]
fn the_old_snapshot_is_kept_on_a_bad_file_and_a_good_change_applies() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let path = directory.path().join("net-topology.yaml");
    fs::write(&path, format!("stale_after_seconds: {STALE_OLD}\n"))?;
    let engine = open_settings_file(&path)?;
    assert_eq!(current_config(&engine).stale_after_seconds, STALE_OLD);
    fs::write(&path, "stale_after_seconds: 0\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).stale_after_seconds, STALE_OLD);
    fs::write(&path, format!("stale_after_seconds: {STALE_OLD}\nunknown: 1\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).stale_after_seconds, STALE_OLD);
    fs::write(&path, format!("stale_after_seconds: {STALE_NEW}\n"))?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).stale_after_seconds, STALE_NEW);
    Ok(())
}


#[test]
fn the_first_file_must_parse_and_validate() -> TestResult {
    let directory = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR"))?;
    let path = directory.path().join("net-topology.yaml");
    fs::write(&path, "max_interfaces: 0\n")?;
    assert!(matches!(open_settings_file(&path), Err(OpenError::Invalid(error)) if error.field == "max_interfaces"));
    fs::write(&path, "bogus: 1\n")?;
    assert!(matches!(open_settings_file(&path), Err(OpenError::Config(_))));
    assert!(matches!(
        open_settings_file(&directory.path().join("absent.yaml")),
        Err(OpenError::Config(_))
    ));
    Ok(())
}
