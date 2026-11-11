use crate::types::{TestError, TestResult};
use axum::Router;
use core_api::server::{listening_address, new_listener, run_loaded, stop_listener};
use core_api::types::AccessTable;
use core_config::load::load_module;
use std::fs;
use std::path::Path;
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
    let task = tokio::spawn(async move { run_loaded(&file, loaded, parts, &START_ONLY, running, None).await });
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
    let task = tokio::spawn(async move { run_loaded(&file, loaded, parts, &START_ONLY, running, None).await });
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
    let task = tokio::spawn(async move { run_loaded(&file, loaded, parts, &START_ONLY, running, None).await });
    listening_address(&listener).await.ok_or("server did not start")?;
    stop_listener(&listener, None);
    assert!(task.await?.is_ok());
    let audit = audit_text(dir.path())?;
    assert!(audit.contains("\"applied\""));
    assert!(!audit.contains(REFUSAL_MARKER));
    Ok(())
}
