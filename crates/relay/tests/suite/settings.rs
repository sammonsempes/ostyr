use crate::support::{audit_text, rig, TestResult, BASE_YAML, HUGE_SOFT};
use core_config::parse::parse_document;
use core_config::reload::{current_config, reload, ReloadOutcome};
use relay::error::SettingsError;
use relay::model::{
    RelaySettings, DEFAULT_CONNECT_TIMEOUT_SECONDS, DEFAULT_IDLE_SECONDS, DEFAULT_MAX_CONNECTIONS, DEFAULT_MAX_CONNECTIONS_PER_SOURCE,
    DEFAULT_MAX_LIFETIME_SECONDS, MAX_CONNECTIONS_LIMIT, MAX_SECONDS_LIMIT, MIN_IDLE_SECONDS, MIN_LIFETIME_SECONDS, RESERVED_FDS,
};
use relay::settings::{
    check_allowlist, check_descriptors, invalid_settings, nofile_soft_limit, read_settings, settings_state, validate_reload, validate_settings,
};
use std::net::SocketAddr;


const TOO_MANY: usize = MAX_CONNECTIONS_LIMIT + 1;


const SMALL_SOFT: u64 = 100;


const NEEDED_FOR_ONE: u64 = 2 + RESERVED_FDS;


const BELOW_MIN_IDLE: u64 = MIN_IDLE_SECONDS - 1;


const BELOW_MIN_LIFETIME: u64 = MIN_LIFETIME_SECONDS - 1;


const OVER_AGENT_CONNECT: u64 = 10;


const SMALL_CAP: usize = 3;


const BIG_CAP: usize = 50;


fn parse(yaml: &str) -> Result<RelaySettings, core_config::error::ConfigError> {
    parse_document(yaml, "relay.yaml")
}


fn faults(yaml: &str) -> Result<Vec<&'static str>, Box<dyn std::error::Error>> {
    Ok(invalid_settings(&parse(yaml)?))
}


fn with(extra: &str) -> String {
    format!("{BASE_YAML}{extra}")
}


#[test]
fn defaults_are_the_documented_constants() -> TestResult {
    let settings = parse(BASE_YAML)?;
    assert_eq!(settings.max_connections, DEFAULT_MAX_CONNECTIONS);
    assert_eq!(settings.max_connections_per_source, DEFAULT_MAX_CONNECTIONS_PER_SOURCE);
    assert_eq!(settings.connect_timeout_seconds, DEFAULT_CONNECT_TIMEOUT_SECONDS);
    assert_eq!(settings.idle_seconds, DEFAULT_IDLE_SECONDS);
    assert_eq!(settings.max_lifetime_seconds, DEFAULT_MAX_LIFETIME_SECONDS);
    assert!(invalid_settings(&settings).is_empty());
    validate_settings(&settings, HUGE_SOFT)?;
    assert!(nofile_soft_limit() > 0);
    Ok(())
}


#[test]
fn every_out_of_bound_value_is_named() -> TestResult {
    assert_eq!(
        faults(&with("max_connections: 0\n"))?,
        vec!["max_connections", "max_connections_per_source"]
    );
    assert_eq!(faults(&with(&format!("max_connections: {TOO_MANY}\n")))?, vec!["max_connections"]);
    assert_eq!(faults(&with("max_connections_per_source: 0\n"))?, vec!["max_connections_per_source"]);
    assert_eq!(
        faults(&with(&format!("max_connections: {SMALL_CAP}\nmax_connections_per_source: {BIG_CAP}\n")))?,
        vec!["max_connections_per_source"]
    );
    assert_eq!(faults(&with("connect_timeout_seconds: 0\n"))?, vec!["connect_timeout_seconds"]);
    assert_eq!(
        faults(&with(&format!("connect_timeout_seconds: {OVER_AGENT_CONNECT}\n")))?,
        vec!["connect_timeout_seconds"]
    );
    assert_eq!(
        faults(&with("idle_seconds: 0\n"))?,
        vec!["idle_seconds", "connect_timeout_seconds must be below idle_seconds"]
    );
    assert_eq!(faults(&with(&format!("idle_seconds: {BELOW_MIN_IDLE}\n")))?, vec!["idle_seconds"]);
    assert_eq!(
        faults(&with(&format!("max_lifetime_seconds: {BELOW_MIN_LIFETIME}\n")))?,
        vec!["max_lifetime_seconds"]
    );
    let over = MAX_SECONDS_LIMIT + 1;
    assert_eq!(faults(&with(&format!("idle_seconds: {over}\n")))?.first().copied(), Some("idle_seconds"));
    assert_eq!(faults(&with(&format!("max_lifetime_seconds: {over}\n")))?, vec!["max_lifetime_seconds"]);
    Ok(())
}


#[test]
fn the_cross_checks_hold() -> TestResult {
    let equal = format!("idle_seconds: {MIN_LIFETIME_SECONDS}\nmax_lifetime_seconds: {MIN_LIFETIME_SECONDS}\n");
    assert!(faults(&with(&equal))?.is_empty());
    let bigger = format!(
        "idle_seconds: {}\nmax_lifetime_seconds: {MIN_LIFETIME_SECONDS}\n",
        MIN_LIFETIME_SECONDS + 1
    );
    assert_eq!(faults(&with(&bigger))?, vec!["idle_seconds must not exceed max_lifetime_seconds"]);
    Ok(())
}


#[test]
fn the_address_rules_hold() -> TestResult {
    let upstream = "upstream: 10.0.0.1:8443\n";
    let listen = "listen: 0.0.0.0:443\n";
    assert_eq!(faults(&format!("listen: 0.0.0.0:0\n{upstream}"))?, vec!["listen"]);
    assert_eq!(faults(&format!("listen: 224.0.0.1:443\n{upstream}"))?, vec!["listen"]);
    assert_eq!(faults(&format!("listen: 255.255.255.255:443\n{upstream}"))?, vec!["listen"]);
    assert!(faults(&format!("listen: \"[::]:443\"\n{upstream}"))?.is_empty());
    assert_eq!(faults(&format!("{listen}upstream: 10.0.0.1:0\n"))?, vec!["upstream"]);
    assert_eq!(faults(&format!("{listen}upstream: 0.0.0.0:8443\n"))?, vec!["upstream"]);
    assert_eq!(faults(&format!("{listen}upstream: 224.0.0.1:8443\n"))?, vec!["upstream"]);
    assert_eq!(faults(&format!("{listen}upstream: 255.255.255.255:8443\n"))?, vec!["upstream"]);
    assert!(faults(&format!("{listen}upstream: \"[2001:db8::1]:8443\"\n"))?.is_empty());
    Ok(())
}


#[test]
fn a_self_loop_is_refused() -> TestResult {
    let named = "upstream is the relay itself";
    assert_eq!(faults("listen: 192.0.2.1:443\nupstream: 192.0.2.1:443\n")?, vec![named]);
    assert_eq!(faults("listen: 0.0.0.0:443\nupstream: 127.0.0.1:443\n")?, vec![named]);
    assert_eq!(faults("listen: \"[::]:443\"\nupstream: \"[::1]:443\"\n")?, vec![named]);
    assert!(faults("listen: 0.0.0.0:443\nupstream: 127.0.0.1:8443\n")?.is_empty());
    assert!(faults("listen: 0.0.0.0:443\nupstream: 10.0.0.1:443\n")?.is_empty());
    assert!(faults("listen: 192.0.2.1:443\nupstream: 127.0.0.1:443\n")?.is_empty());
    Ok(())
}


#[test]
fn an_ipv4_mapped_upstream_is_folded() -> TestResult {
    let settings = parse("listen: 0.0.0.0:443\nupstream: \"[::ffff:10.0.0.1]:8443\"\n")?;
    assert_eq!(settings.upstream, "10.0.0.1:8443".parse::<SocketAddr>()?);
    Ok(())
}


#[test]
fn an_unparsable_address_never_repeats_its_text() -> TestResult {
    let refused = parse("listen: marker-text-xyz\nupstream: 10.0.0.1:8443\n");
    let text = format!("{refused:?}");
    assert!(refused.is_err());
    assert!(!text.contains("marker-text-xyz"));
    Ok(())
}


#[test]
fn an_unknown_key_is_refused() -> TestResult {
    assert!(parse(&with("surprise: 1\n")).is_err());
    Ok(())
}


#[test]
fn the_descriptor_check_names_the_limit() -> TestResult {
    check_descriptors(1, NEEDED_FOR_ONE)?;
    let refused = check_descriptors(1, NEEDED_FOR_ONE - 1);
    assert!(matches!(refused, Err(SettingsError::Descriptors { max: 1, soft, .. }) if soft == NEEDED_FOR_ONE - 1));
    assert!(check_descriptors(usize::MAX, SMALL_SOFT).is_err());
    let settings = parse(BASE_YAML)?;
    let refused_default = validate_settings(&settings, SMALL_SOFT);
    assert!(refused_default.is_err());
    assert!(refused_default
        .err()
        .map(|error| error.to_string())
        .is_some_and(|text| text.contains("RLIMIT_NOFILE")));
    Ok(())
}


#[test]
fn an_invalid_first_load_is_refused_with_the_names() -> TestResult {
    let refused = validate_settings(&parse(&with("max_connections: 0\n"))?, HUGE_SOFT);
    assert!(matches!(refused, Err(SettingsError::Invalid(names)) if names.contains("max_connections")));
    Ok(())
}


#[test]
fn the_engine_refuses_an_invalid_first_file() -> TestResult {
    let refused = rig(&with("max_connections: 0\n"));
    assert!(refused.is_err());
    let missing = rig("listen: 0.0.0.0:443\n");
    assert!(missing.is_err());
    Ok(())
}


#[test]
fn reload_validate_pins_listen() -> TestResult {
    let started: SocketAddr = "0.0.0.0:443".parse()?;
    let same = parse(BASE_YAML)?;
    validate_reload(&same, started, HUGE_SOFT)?;
    let moved = parse("listen: 0.0.0.0:444\nupstream: 10.0.0.1:8443\n")?;
    assert!(matches!(validate_reload(&moved, started, HUGE_SOFT), Err(SettingsError::ListenChanged)));
    Ok(())
}


#[test]
fn state_lists_every_field() -> TestResult {
    let state = settings_state(&parse(BASE_YAML)?);
    assert_eq!(state.get("relay.idle_seconds").map(String::as_str), Some("120"));
    assert!(state.contains_key("relay.upstream"));
    Ok(())
}


#[test]
fn a_reload_swaps_upstream_and_audits() -> TestResult {
    let rig = rig(BASE_YAML)?;
    std::fs::write(&rig.settings_path, "listen: 0.0.0.0:443\nupstream: 10.0.0.2:8443\n")?;
    let outcome = reload(&rig.engine);
    assert!(matches!(outcome, ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&rig.engine).upstream, "10.0.0.2:8443".parse::<SocketAddr>()?);
    assert!(audit_text(&rig)?.contains("applied"));
    assert_eq!(reload(&rig.engine), ReloadOutcome::Unchanged);
    Ok(())
}


#[test]
fn a_changed_listen_refuses_the_whole_reload() -> TestResult {
    let rig = rig(BASE_YAML)?;
    std::fs::write(&rig.settings_path, "listen: 0.0.0.0:444\nupstream: 10.0.0.2:8443\n")?;
    let outcome = reload(&rig.engine);
    assert!(matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains("read at start only")));
    assert_eq!(current_config(&rig.engine).upstream, "10.0.0.1:8443".parse::<SocketAddr>()?);
    let audit = audit_text(&rig)?;
    assert!(audit.contains("denied"));
    assert!(audit.contains("read at start only"));
    Ok(())
}


#[test]
fn an_invalid_reload_keeps_the_old_settings() -> TestResult {
    let rig = rig(BASE_YAML)?;
    std::fs::write(&rig.settings_path, with("idle_seconds: 0\n"))?;
    assert!(matches!(reload(&rig.engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&rig.engine).idle_seconds, DEFAULT_IDLE_SECONDS);
    std::fs::write(&rig.settings_path, with("surprise: 1\n"))?;
    assert!(matches!(reload(&rig.engine), ReloadOutcome::Refused { .. }));
    Ok(())
}


fn refused_bytes(bytes: &[u8]) -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("relay.yaml");
    std::fs::write(&path, bytes)?;
    let refused = read_settings(&path);
    assert!(refused.is_err(), "{bytes:?} was accepted");
    assert!(refused.err().is_some_and(|error| error.to_string().contains("allowlist")));
    Ok(())
}


#[test]
fn the_allowlist_refuses_yaml_features() -> TestResult {
    let cases: &[&[u8]] = &[
        b"listen: !!str 0.0.0.0:443\nupstream: 10.0.0.1:8443\n",
        b"listen: &a 0.0.0.0:443\nupstream: 10.0.0.1:8443\n",
        b"listen: 0.0.0.0:443\nupstream: *a\n",
        b"<<: {max_connections: 5}\nlisten: 0.0.0.0:443\nupstream: 10.0.0.1:8443\n",
        b"listen: \"0.0.0.0:\\x34\\x34\\x33\"\nupstream: 10.0.0.1:8443\n",
        b"listen: |\n  0.0.0.0:443\nupstream: 10.0.0.1:8443\n",
        b"listen: >\n  0.0.0.0:443\nupstream: 10.0.0.1:8443\n",
        b"listen: 0.0.0.0:443\rupstream: 10.0.0.1:8443\n",
        b"listen: 0.0.0.0:443\n\tupstream: 10.0.0.1:8443\n",
        "listen: 0.0.0.0:443\nupstream: 10.0.0.1:8443\n# caf\u{e9}\n".as_bytes(),
        b"# comment\nlisten: 0.0.0.0:443\nupstream: 10.0.0.1:8443\n",
        b"listen: 0.0.0.0:443\0\nupstream: 10.0.0.1:8443\n",
    ];
    cases.iter().try_for_each(|bytes| refused_bytes(bytes))
}


#[test]
fn the_allowlist_accepts_a_plain_file() -> TestResult {
    check_allowlist(BASE_YAML.as_bytes(), "relay.yaml")?;
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("relay.yaml");
    std::fs::write(&path, BASE_YAML)?;
    assert_eq!(read_settings(&path)?.upstream, "10.0.0.1:8443".parse::<SocketAddr>()?);
    Ok(())
}


#[test]
fn an_oversized_file_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = dir.path().join("relay.yaml");
    std::fs::write(&path, " ".repeat(usize::try_from(relay::model::MAX_SETTINGS_BYTES)? + 1))?;
    assert!(read_settings(&path).is_err());
    Ok(())
}
