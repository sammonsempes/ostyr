use core_config::error::ConfigError;
use core_config::load::{load_module, load_module_for_tenant};
use core_config::reload::layered_loader;
use std::error::Error;
use std::fs;
use std::path::Path;


fn module_file(directory: &Path, name: &str, tenant: &str) -> Result<std::path::PathBuf, std::io::Error> {
    let path = directory.join(name);
    fs::write(&path, format!("name: siem\nversion: 1.2.0\ntenant: {tenant}\n")).map(|()| path)
}


fn refusal_reason(result: Result<core_config::model::ModuleConfig, ConfigError>) -> Option<&'static str> {
    match result {
        Err(ConfigError::Tenant { reason, .. }) => Some(reason),
        _ => None,
    }
}


#[test]
fn reserved_and_invalid_module_tenants_are_refused_named() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    ["ALL", "all", "Platform"].iter().try_for_each(|tenant| -> Result<(), Box<dyn Error>> {
        let path = module_file(directory.path(), "reserved.yaml", tenant)?;
        assert_eq!(refusal_reason(load_module(&path)), Some("reserved name"), "{tenant}");
        Ok(())
    })?;
    let path = module_file(directory.path(), "grammar.yaml", "-x")?;
    let error = load_module(&path).err().ok_or("expected a refusal")?.to_string();
    assert!(
        error.contains("grammar.yaml") && error.contains("`tenant` refused: not a valid tenant name"),
        "{error}"
    );
    Ok(())
}


#[test]
fn customer_and_absent_tenants_load() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    ["alla", "all-1", "default"].iter().try_for_each(|tenant| -> Result<(), Box<dyn Error>> {
        let path = module_file(directory.path(), "ok.yaml", tenant)?;
        assert_eq!(load_module(&path)?.tenant.as_deref(), Some(*tenant));
        Ok(())
    })?;
    let absent = directory.path().join("absent.yaml");
    fs::write(&absent, "name: siem\nversion: 1.2.0\n")?;
    assert!(load_module(&absent)?.tenant.is_none());
    Ok(())
}


#[test]
fn the_layered_forms_refuse_a_reserved_tenant() -> Result<(), Box<dyn Error>> {
    let directory = tempfile::tempdir()?;
    let base = directory.path().join("base.yaml");
    fs::write(&base, "name: siem\nversion: 1.2.0\n")?;
    let overlay = directory.path().join("overlay.yaml");
    fs::write(&overlay, "tenant: ALL\n")?;
    assert_eq!(refusal_reason(load_module_for_tenant(&base, &overlay)), Some("reserved name"));
    assert_eq!(refusal_reason(layered_loader(base, overlay)()), Some("reserved name"));
    Ok(())
}
