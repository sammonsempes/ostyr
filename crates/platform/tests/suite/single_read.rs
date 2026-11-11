use crate::types::{TestError, TestResult};
use alerts::settings::{open_pg_engine_from, startup_reload};
use axum::Router;
use core_api::server::{listening_address, new_listener, run_loaded, stop_listener};
use core_api::types::{AccessTable, StartupReloadFn};
use core_config::load::load_module;
use core_config::reload::{current_config, ReloadOutcome};
use std::fs;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, PoisonError};
use tempfile::tempdir;


const KEY_BYTES: usize = 32;


const KEY_FILL: u8 = 9;


const START_ONLY: [&str; 1] = ["modules"];


const REFUSAL_MARKER: &str = "read at start only";


#[cfg(unix)]
fn private_file(path: &Path, bytes: &[u8]) -> Result<(), TestError> {
    use std::os::unix::fs::PermissionsExt;
    const OWNER_ONLY: u32 = 0o600;
    fs::write(path, bytes)?;
    fs::set_permissions(path, fs::Permissions::from_mode(OWNER_ONLY))?;
    Ok(())
}


#[cfg(not(unix))]
fn private_file(path: &Path, bytes: &[u8]) -> Result<(), TestError> {
    fs::write(path, bytes)?;
    Ok(())
}


fn module_text(dir: &Path) -> String {
    format!(
        "name: platform\nversion: \"1\"\nlisten: \"127.0.0.1:0\"\nsettings:\n  modules: \"alerts,cases,cmdb\"\n  accounts_store: {}\n  audit_log: {}\n  key_file: {}\n  compromised_list: {}\n",
        dir.join("accounts.json").display(),
        dir.join("audit.log").display(),
        dir.join("store.key").display(),
        dir.join("compromised.txt").display(),
    )
}


fn audit_text(dir: &Path) -> Result<String, TestError> {
    Ok(fs::read_to_string(dir.join("audit.log"))?)
}


#[tokio::test]
async fn the_start_only_baseline_is_the_loaded_value_not_a_second_read() -> TestResult {
    let dir = tempdir()?;
    private_file(&dir.path().join("store.key"), &[KEY_FILL; KEY_BYTES])?;
    fs::write(dir.path().join("compromised.txt"), "passwordpassword\n")?;
    let text = module_text(dir.path());
    let module_file = dir.path().join("platform.yaml");
    fs::write(&module_file, &text)?;
    let mut loaded = load_module(&module_file)?;
    loaded.settings.insert("modules".to_owned(), "alerts".to_owned());
    let listener = new_listener();
    let running = listener.clone();
    let file = module_file.clone();
    let parts = (Router::new(), AccessTable::new(), vec![]);
    let task = tokio::spawn(async move { run_loaded(&file, loaded, parts, &START_ONLY, running, None, Vec::new()).await });
    listening_address(&listener).await.ok_or("server did not start")?;
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    let audit = audit_text(dir.path())?;
    assert!(audit.contains(REFUSAL_MARKER));
    assert!(!audit.contains("\"applied\""));
    Ok(())
}


#[tokio::test]
async fn a_file_unchanged_since_the_load_leaves_no_reload_record() -> TestResult {
    let dir = tempdir()?;
    private_file(&dir.path().join("store.key"), &[KEY_FILL; KEY_BYTES])?;
    fs::write(dir.path().join("compromised.txt"), "passwordpassword\n")?;
    let module_file = dir.path().join("platform.yaml");
    fs::write(&module_file, module_text(dir.path()))?;
    let loaded = load_module(&module_file)?;
    let listener = new_listener();
    let running = listener.clone();
    let file = module_file.clone();
    let parts = (Router::new(), AccessTable::new(), vec![]);
    let task = tokio::spawn(async move { run_loaded(&file, loaded, parts, &START_ONLY, running, None, Vec::new()).await });
    listening_address(&listener).await.ok_or("server did not start")?;
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    let audit = audit_text(dir.path())?;
    assert!(!audit.contains(REFUSAL_MARKER));
    assert!(!audit.contains("\"applied\""));
    Ok(())
}


#[tokio::test]
async fn an_allowed_change_made_during_startup_is_applied_by_the_startup_reload() -> TestResult {
    let dir = tempdir()?;
    private_file(&dir.path().join("store.key"), &[KEY_FILL; KEY_BYTES])?;
    fs::write(dir.path().join("compromised.txt"), "passwordpassword\n")?;
    let module_file = dir.path().join("platform.yaml");
    fs::write(&module_file, module_text(dir.path()))?;
    let mut loaded = load_module(&module_file)?;
    loaded.settings.insert("log_level".to_owned(), "debug".to_owned());
    let listener = new_listener();
    let running = listener.clone();
    let file = module_file.clone();
    let parts = (Router::new(), AccessTable::new(), vec![]);
    let task = tokio::spawn(async move { run_loaded(&file, loaded, parts, &START_ONLY, running, None, Vec::new()).await });
    listening_address(&listener).await.ok_or("server did not start")?;
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    let audit = audit_text(dir.path())?;
    assert!(audit.contains("\"applied\""));
    assert!(!audit.contains(REFUSAL_MARKER));
    Ok(())
}


const PG_TEXT: &str = "host: 127.0.0.1\nport: 5432\ndatabase: ostyr\nuser: ostyr\npassword_file: /run/pg.pass\nca_file: /run/ca.pem\n";


const PG_EDITED: &str = "host: 127.0.0.2\nport: 5432\ndatabase: ostyr\nuser: ostyr\npassword_file: /run/pg.pass\nca_file: /run/ca.pem\n";


const PG_FILE_NAME: &str = "pg.yaml";


async fn serve_with_pg_engine(dir: &Path, edit_after_open: Option<&str>) -> Result<String, TestError> {
    private_file(&dir.join("store.key"), &[KEY_FILL; KEY_BYTES])?;
    fs::write(dir.join("compromised.txt"), "passwordpassword\n")?;
    let pg_file = dir.join(PG_FILE_NAME);
    fs::write(&pg_file, PG_TEXT)?;
    let module_file = dir.join("platform.yaml");
    fs::write(&module_file, format!("{}  pg_settings: {}\n", module_text(dir), pg_file.display()))?;
    let loaded = load_module(&module_file)?;
    let listener = new_listener();
    let (opened, _pg_file) = open_pg_engine_from(&module_file, &loaded, listener.clone(), "platform")?;
    let engine = Arc::new(opened);
    edit_after_open.iter().try_for_each(|text| fs::write(&pg_file, text))?;
    let running = listener.clone();
    let parts = (Router::new(), AccessTable::new(), vec![]);
    let startup = vec![startup_reload(Arc::clone(&engine))];
    let task = tokio::spawn(async move { run_loaded(&module_file, loaded, parts, &START_ONLY, running, None, startup).await });
    listening_address(&listener).await.ok_or("server did not start")?;
    stop_listener(&listener, None);
    task.await??;
    assert_eq!(current_config(&engine).host, edit_after_open.map_or("127.0.0.1", |_| "127.0.0.2"));
    audit_text(dir)
}


#[tokio::test]
async fn a_pg_file_edit_made_before_run_loaded_is_audited_by_the_startup_reload() -> TestResult {
    let dir = tempdir()?;
    let audit = serve_with_pg_engine(dir.path(), Some(PG_EDITED)).await?;
    let pg_records = audit.lines().filter(|line| line.contains(PG_FILE_NAME)).count();
    assert_eq!(pg_records, 1, "{audit}");
    assert!(audit.contains("\"applied\""));
    Ok(())
}


#[tokio::test]
async fn an_unchanged_pg_file_leaves_no_record_at_startup() -> TestResult {
    let dir = tempdir()?;
    let audit = serve_with_pg_engine(dir.path(), None).await?;
    assert!(!audit.contains(PG_FILE_NAME), "{audit}");
    Ok(())
}


#[tokio::test]
async fn the_extra_startup_reloads_run_before_the_first_generation_serves() -> TestResult {
    let dir = tempdir()?;
    private_file(&dir.path().join("store.key"), &[KEY_FILL; KEY_BYTES])?;
    fs::write(dir.path().join("compromised.txt"), "passwordpassword\n")?;
    let module_file = dir.path().join("platform.yaml");
    fs::write(&module_file, module_text(dir.path()))?;
    let loaded = load_module(&module_file)?;
    let listener = new_listener();
    let running = listener.clone();
    let probe = listener.clone();
    let ran = Arc::new(AtomicBool::new(false));
    let served_before = Arc::new(AtomicBool::new(true));
    let (ran_flag, served_flag) = (ran.clone(), served_before.clone());
    let startup: Vec<StartupReloadFn> = vec![Box::new(move || {
        let bound = probe.current.lock().unwrap_or_else(PoisonError::into_inner).bound.is_some();
        served_flag.store(bound, Ordering::SeqCst);
        ran_flag.store(true, Ordering::SeqCst);
        ReloadOutcome::Unchanged
    })];
    let parts = (Router::new(), AccessTable::new(), vec![]);
    let task = tokio::spawn(async move { run_loaded(&module_file, loaded, parts, &START_ONLY, running, None, startup).await });
    listening_address(&listener).await.ok_or("server did not start")?;
    stop_listener(&listener, None);
    task.await??;
    assert!(ran.load(Ordering::SeqCst));
    assert!(!served_before.load(Ordering::SeqCst));
    Ok(())
}
