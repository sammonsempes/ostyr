#[path = "common/types.rs"]
mod types;


use core_config::error::ConfigError;
use core_config::model::{ModuleConfig, PlatformConfig};
use core_config::schema::{schema_text, write_schemas, MODULE_SCHEMA_FILE, PLATFORM_SCHEMA_FILE};
use std::fs;
use std::path::PathBuf;
use types::TestResult;


const EXPECTED_SCHEMA_FILES: usize = 2;


fn committed_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..").join("..").join("schemas")
}


#[test]
fn schemas_are_written() -> TestResult {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("out");
    let written = write_schemas(&target)?;
    assert_eq!(written.len(), EXPECTED_SCHEMA_FILES);
    assert_eq!(fs::read_to_string(target.join(PLATFORM_SCHEMA_FILE))?, schema_text::<PlatformConfig>());
    let module: serde_json::Value = serde_json::from_str(&fs::read_to_string(target.join(MODULE_SCHEMA_FILE))?)?;
    assert_eq!(module.get("additionalProperties"), Some(&serde_json::Value::Bool(false)));
    Ok(())
}


#[test]
fn secret_fields_carry_the_reference_pattern() -> TestResult {
    let text = schema_text::<ModuleConfig>();
    assert!(text.contains("vault://|openbao://|sops:"), "{text}");
    Ok(())
}


#[test]
fn committed_schemas_are_up_to_date() -> TestResult {
    let committed_platform = fs::read_to_string(committed_dir().join(PLATFORM_SCHEMA_FILE))?;
    let committed_module = fs::read_to_string(committed_dir().join(MODULE_SCHEMA_FILE))?;
    assert_eq!(committed_platform, schema_text::<PlatformConfig>());
    assert_eq!(committed_module, schema_text::<ModuleConfig>());
    Ok(())
}


#[test]
fn directory_creation_failure_is_reported() -> TestResult {
    let dir = tempfile::tempdir()?;
    let blocker = dir.path().join("file");
    fs::write(&blocker, "x")?;
    let result = write_schemas(&blocker.join("sub"));
    assert!(matches!(result, Err(ConfigError::Io { .. })));
    Ok(())
}


#[test]
fn file_write_failure_is_reported() -> TestResult {
    let dir = tempfile::tempdir()?;
    fs::create_dir(dir.path().join(PLATFORM_SCHEMA_FILE))?;
    assert!(matches!(write_schemas(dir.path()), Err(ConfigError::Io { .. })));
    fs::remove_dir(dir.path().join(PLATFORM_SCHEMA_FILE))?;
    fs::create_dir(dir.path().join(MODULE_SCHEMA_FILE))?;
    assert!(matches!(write_schemas(dir.path()), Err(ConfigError::Io { .. })));
    Ok(())
}
