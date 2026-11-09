use core_audit::log::{append, genesis_log};
use core_audit::model::NewEntry;
use core_config::reload::{current_config, reload, ReloadContext, ReloadOutcome};
use core_pg::settings::{
    check_host, check_name, check_path, load_settings, open_settings, parse_settings, settings_state, DEFAULT_CONNECT_TIMEOUT_SECS, DEFAULT_PORT,
    DEFAULT_STATEMENT_TIMEOUT_SECS,
};
use std::error::Error;
use std::fs;
use std::io;
use tempfile::tempdir;


const FULL_PORT: u16 = 6432;


const FULL_CONNECT: u64 = 7;


const FULL_STATEMENT: u64 = 11;


const OVER_LONG: usize = 256;


const STATE_KEYS: usize = 8;


const FULL: &str = "host: db.example\nport: 6432\ndatabase: ostyr\nuser: ostyr\npassword_file: /etc/ostyr/pg.pass\nca_file: /etc/ostyr/ca.pem\n\
connect_timeout_secs: 7\nstatement_timeout_secs: 11\n";


const MINIMAL: &str = "host: 10.0.0.5\ndatabase: ostyr\nuser: ostyr\npassword_file: p\nca_file: c\n";


fn context() -> ReloadContext {
    ReloadContext {
        actor_id: "core-pg".to_owned(),
        tenant: "example".to_owned(),
        module: "pg".to_owned(),
        target: "pg.yaml".to_owned(),
        request_id: "reload".to_owned(),
    }
}


#[test]
fn full_document_parses() -> Result<(), Box<dyn Error>> {
    let settings = parse_settings(FULL, "pg.yaml")?;
    assert_eq!(settings.host, "db.example");
    assert_eq!(settings.port, FULL_PORT);
    assert_eq!(settings.connect_timeout_secs, FULL_CONNECT);
    assert_eq!(settings.statement_timeout_secs, FULL_STATEMENT);
    Ok(())
}


#[test]
fn defaults_apply() -> Result<(), Box<dyn Error>> {
    let settings = parse_settings(MINIMAL, "pg.yaml")?;
    assert_eq!(settings.port, DEFAULT_PORT);
    assert_eq!(settings.connect_timeout_secs, DEFAULT_CONNECT_TIMEOUT_SECS);
    assert_eq!(settings.statement_timeout_secs, DEFAULT_STATEMENT_TIMEOUT_SECS);
    Ok(())
}


const BASE_FIELDS: [(&str, &str); 5] = [
    ("host", "10.0.0.5"),
    ("database", "ostyr"),
    ("user", "ostyr"),
    ("password_file", "p"),
    ("ca_file", "c"),
];


fn document_with(key: &str, value: &str) -> String {
    let kept = BASE_FIELDS
        .iter()
        .filter(|(name, _)| *name != key)
        .map(|(name, text)| format!("{name}: {text}\n"));
    kept.chain(std::iter::once(format!("{key}: {value}\n"))).collect()
}


#[test]
fn invalid_documents_are_refused_with_the_field_path() -> Result<(), Box<dyn Error>> {
    let cases = [
        ("host", "/var/run/postgresql"),
        ("host", "-evil"),
        ("host", "\"a b\""),
        ("host", "\"\""),
        ("database", "-x"),
        ("user", "\"\""),
        ("password_file", "\"\""),
        ("ca_file", "\"a\\nb\""),
        ("connect_timeout_secs", "0"),
        ("statement_timeout_secs", "3601"),
    ];
    cases.iter().try_for_each(|(field, value)| {
        let message = parse_settings(&document_with(field, value), "pg.yaml")
            .err()
            .map(|error| error.to_string())
            .ok_or("accepted")?;
        assert!(message.contains(field), "{field}={value}: {message}");
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn unknown_fields_are_refused() -> Result<(), Box<dyn Error>> {
    let result = parse_settings(&document_with("sslmode", "disable"), "pg.yaml");
    assert!(result.is_err_and(|error| error.to_string().contains("unknown field")));
    Ok(())
}


#[test]
fn field_checks_accept_and_refuse() -> Result<(), Box<dyn Error>> {
    assert!(check_host("db-1.example.net").is_ok());
    assert!(check_host("2001:db8::1").is_ok());
    assert!(check_host("/tmp").is_err());
    assert!(check_host(&"a".repeat(OVER_LONG)).is_err());
    assert!(check_name("o'str").is_ok());
    assert!(check_name("-x").is_err());
    assert!(check_name(&"a".repeat(OVER_LONG)).is_err());
    assert!(check_path("/etc/x").is_ok());
    assert!(check_path("").is_err());
    Ok(())
}


#[test]
fn state_lists_every_setting_without_secrets() -> Result<(), Box<dyn Error>> {
    let state = settings_state(&parse_settings(FULL, "pg.yaml")?);
    assert_eq!(state.len(), STATE_KEYS);
    assert_eq!(state.get("password_file").map(String::as_str), Some("/etc/ostyr/pg.pass"));
    Ok(())
}


#[test]
fn missing_file_is_an_error() -> Result<(), Box<dyn Error>> {
    let dir = tempdir().map(|handle| handle.path().join("absent.yaml"));
    assert!(dir.is_ok_and(|path| load_settings(&path).is_err()));
    Ok(())
}


#[test]
fn reload_swaps_for_new_snapshots_only() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = dir.path().join("pg.yaml");
    fs::write(&path, FULL)?;
    let log = genesis_log(io::sink());
    let audit = move |entry: NewEntry| append(&log, entry);
    let engine = open_settings(path.clone(), Box::new(audit), context())?;
    let held = current_config(&engine);
    fs::write(&path, FULL.replace("db.example", "db2.example"))?;
    assert_eq!(
        reload(&engine),
        ReloadOutcome::Applied {
            keys: vec!["host".to_owned()]
        }
    );
    assert_eq!(held.host, "db.example");
    assert_eq!(current_config(&engine).host, "db2.example");
    fs::write(&path, "host: -bad\n")?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).host, "db2.example");
    Ok(())
}
