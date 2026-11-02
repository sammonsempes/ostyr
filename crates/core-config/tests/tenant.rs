mod common;


use common::fixture;
use core_config::error::ConfigError;
use core_config::load::{load_layered, load_module_for_tenant};
use core_config::merge::merge_documents;
use core_config::model::PlatformConfig;
use core_config::parse::parse_document;
use std::error::Error;


type TestResult = Result<(), Box<dyn Error>>;


#[test]
fn tenant_overrides_base() -> TestResult {
    let module = load_module_for_tenant(&fixture("base/module.yaml"), &fixture("tenant/module.yaml"))?;
    assert_eq!(module.name, "siem");
    assert_eq!(module.tenant.as_deref(), Some("acme"));
    assert!(module.listen.is_none());
    assert_eq!(module.secrets.len(), 2);
    assert_eq!(module.secrets.get("db").map(|secret| secret.0.as_str()), Some("vault://kv/acme/db"));
    assert_eq!(
        module.secrets.get("tls").map(|secret| secret.0.as_str()),
        Some("sops:secrets/base.enc.yaml")
    );
    assert_eq!(module.settings.get("retention").map(String::as_str), Some("90d"));
    assert_eq!(module.settings.get("region").map(String::as_str), Some("eu"));
    assert_eq!(module.settings.get("tier").map(String::as_str), Some("gold"));
    Ok(())
}


#[test]
fn sequences_are_replaced_not_concatenated() -> TestResult {
    let merged = merge_documents(
        "modules: [{name: a, version: '1', endpoint: e}]\n",
        "base",
        "modules: [{name: b, version: '2', endpoint: f}]\n",
        "tenant",
    )?;
    let platform: PlatformConfig = parse_document(&merged, "merged")?;
    assert_eq!(platform.modules.len(), 1);
    assert_eq!(platform.modules.first().map(|module| module.name.as_str()), Some("b"));
    Ok(())
}


#[test]
fn plaintext_secret_in_tenant_is_rejected_in_the_merged_document() -> TestResult {
    let result = load_module_for_tenant(&fixture("base/module.yaml"), &fixture("tenant/module_bad.yaml"));
    match result {
        Err(ConfigError::Parse { file, field_path, line, .. }) => {
            assert!(file.contains("module_bad.yaml (merged over "), "{file}");
            assert_eq!(field_path, "secrets.db");
            assert!(line > 1);
        }
        other => return Err(format!("unexpected {other:?}").into()),
    }
    Ok(())
}


#[test]
fn wrong_type_in_tenant_is_rejected() -> TestResult {
    let result = load_module_for_tenant(&fixture("base/module.yaml"), &fixture("tenant/module_wrong_type.yaml"));
    assert!(matches!(result, Err(ConfigError::Parse { ref field_path, .. }) if field_path == "tenant"));
    Ok(())
}


#[test]
fn scalar_overlay_replaces_the_document() -> TestResult {
    let result = load_module_for_tenant(&fixture("base/module.yaml"), &fixture("tenant/module_scalar.yaml"));
    assert!(matches!(result, Err(ConfigError::Parse { .. })));
    Ok(())
}


#[test]
fn syntax_error_in_a_layer_names_that_layer() -> TestResult {
    let broken = fixture("module_syntax.yaml");
    let base_broken = load_layered::<PlatformConfig>(&broken, &fixture("tenant/module.yaml"))
        .err()
        .ok_or("no error")?;
    assert!(base_broken.to_string().contains("module_syntax.yaml"));
    let overlay_broken = load_layered::<PlatformConfig>(&fixture("base/module.yaml"), &broken)
        .err()
        .ok_or("no error")?;
    assert!(overlay_broken.to_string().contains("module_syntax.yaml"));
    Ok(())
}


#[test]
fn missing_layer_is_an_io_error() -> TestResult {
    let no_base = load_module_for_tenant(&fixture("absent.yaml"), &fixture("tenant/module.yaml"));
    assert!(matches!(no_base, Err(ConfigError::Io { .. })));
    let no_tenant = load_module_for_tenant(&fixture("base/module.yaml"), &fixture("absent.yaml"));
    assert!(matches!(no_tenant, Err(ConfigError::Io { .. })));
    Ok(())
}
