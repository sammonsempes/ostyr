#![cfg(unix)]

use crate::types::TestResult;
use core_config::error::ConfigError;
use core_config::load::load_module;
use core_pg::settings::load_settings;
use risk_score::weights::weights_loader;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;


fn fifo_at(path: &Path) -> TestResult {
    assert!(Command::new("mkfifo").arg(path).status()?.success());
    Ok(())
}


fn refused_as_not_regular<Value>(result: Result<Value, ConfigError>, path: &Path) -> bool {
    matches!(result, Err(ConfigError::WatchedFile { file, reason }) if reason == "not a regular file" && file == path.display().to_string())
}


#[test]
fn a_fifo_at_the_module_file_the_weights_file_or_the_pg_settings_is_refused_without_blocking() -> TestResult {
    let dir = tempdir()?;
    let module = dir.path().join("module.yaml");
    let weights = dir.path().join("weights.yaml");
    let pg_settings = dir.path().join("pg.yaml");
    [&module, &weights, &pg_settings].iter().try_for_each(|path| fifo_at(path))?;
    assert!(refused_as_not_regular(load_module(&module), &module));
    assert!(refused_as_not_regular(weights_loader(weights.clone())(), &weights));
    assert!(refused_as_not_regular(load_settings(&pg_settings), &pg_settings));
    Ok(())
}
