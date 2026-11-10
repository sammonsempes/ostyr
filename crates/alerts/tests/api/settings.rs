use crate::fixture::{fixture, Fixture};
use crate::types::{TestError, TestResult};
use alerts::settings::{check_unchanged, open_pg_engine, pg_file_of};
use core_api::server::new_listener;
use core_config::load::load_module;
use core_config::reload::{current_config, reload, ReloadOutcome};
use std::fs;
use std::path::PathBuf;


const PG_TEXT: &str = "host: 127.0.0.1\nport: 5432\ndatabase: ostyr\nuser: ostyr\npassword_file: /run/pg.pass\nca_file: /run/ca.pem\n";


const OTHER_HOST: &str = "host: 127.0.0.2\nport: 5432\ndatabase: ostyr\nuser: ostyr\npassword_file: /run/pg.pass\nca_file: /run/ca.pem\n";


fn module_text(pg_file: &str) -> String {
    format!("name: alerts\nversion: \"1\"\ntenant: acme\nsettings:\n  pg_settings: {pg_file}\n")
}


struct Files {
    module: PathBuf,
    pg: PathBuf,
    audit: PathBuf,
}


fn files_of(fx: &Fixture) -> Result<Files, TestError> {
    let files = Files {
        module: fx._dir.path().join("alerts.yaml"),
        pg: fx._dir.path().join("pg.yaml"),
        audit: fx._dir.path().join("audit.log"),
    };
    fs::write(&files.module, module_text(&files.pg.display().to_string()))?;
    fs::write(&files.pg, PG_TEXT)?;
    Ok(files)
}


#[test]
fn a_module_without_the_setting_is_refused() -> TestResult {
    let fx = fixture()?;
    let module = fx._dir.path().join("bare.yaml");
    fs::write(&module, "name: alerts\nversion: \"1\"\n")?;
    assert!(pg_file_of(&module, &load_module(&module)?).is_err());
    assert!(open_pg_engine(&module, new_listener()).is_err());
    assert!(check_unchanged(&module, &fx._dir.path().join("pg.yaml")).is_err());
    Ok(())
}


#[test]
fn a_reload_of_the_pg_file_is_audited_in_the_module_audit_log() -> TestResult {
    let fx = fixture()?;
    let files = files_of(&fx)?;
    let listener = new_listener();
    listener.state.get_or_init(|| fx.state.clone());
    let (engine, pg_file) = open_pg_engine(&files.module, listener)?;
    assert_eq!(pg_file, files.pg);
    let before = fs::read_to_string(&files.audit)?;
    fs::write(&files.pg, OTHER_HOST)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Applied { .. }));
    assert_eq!(current_config(&engine).host, "127.0.0.2");
    let after = fs::read_to_string(&files.audit)?;
    assert!(after.len() > before.len());
    assert!(after.contains("config.reload"), "{after}");
    Ok(())
}


#[test]
fn a_change_of_the_settings_file_name_is_refused_and_audited() -> TestResult {
    let fx = fixture()?;
    let files = files_of(&fx)?;
    let listener = new_listener();
    listener.state.get_or_init(|| fx.state.clone());
    let (engine, _pg_file) = open_pg_engine(&files.module, listener)?;
    let moved = fx._dir.path().join("moved.yaml");
    fs::write(&moved, OTHER_HOST)?;
    fs::write(&files.module, module_text(&moved.display().to_string()))?;
    let outcome = reload(&engine);
    assert!(
        matches!(&outcome, ReloadOutcome::Refused { reason } if reason.contains("read at start only")),
        "{outcome:?}"
    );
    assert_eq!(current_config(&engine).host, "127.0.0.1");
    let audit = fs::read_to_string(&files.audit)?;
    assert!(audit.contains("denied") && audit.contains("read at start only"), "{audit}");
    Ok(())
}


#[test]
fn a_reload_before_the_audit_log_is_open_is_refused_and_keeps_the_old_settings() -> TestResult {
    let fx = fixture()?;
    let files = files_of(&fx)?;
    let (engine, _pg_file) = open_pg_engine(&files.module, new_listener())?;
    fs::write(&files.pg, OTHER_HOST)?;
    assert!(matches!(reload(&engine), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&engine).host, "127.0.0.1");
    Ok(())
}


#[test]
fn an_unreadable_module_or_pg_file_is_refused() -> TestResult {
    let fx = fixture()?;
    let files = files_of(&fx)?;
    let absent = fx._dir.path().join("absent.yaml");
    assert!(check_unchanged(&absent, &files.pg).is_err());
    assert!(open_pg_engine(&absent, new_listener()).is_err());
    fs::remove_file(&files.pg)?;
    assert!(open_pg_engine(&files.module, new_listener()).is_err());
    Ok(())
}


#[test]
fn a_module_without_a_tenant_opens_under_the_default_one() -> TestResult {
    let fx = fixture()?;
    let files = files_of(&fx)?;
    let text = format!("name: alerts\nversion: \"1\"\nsettings:\n  pg_settings: {}\n", files.pg.display());
    fs::write(&files.module, text)?;
    let (engine, _pg_file) = open_pg_engine(&files.module, new_listener())?;
    assert_eq!(current_config(&engine).host, "127.0.0.1");
    Ok(())
}
