use crate::error::ConfigError;
use crate::merge::merge_documents;
use crate::model::{ModuleConfig, PlatformConfig};
use crate::parse::{parse_document, read_file};
use core_audit::tenant::{is_reserved_tenant, is_valid_tenant_grammar};
use serde::de::DeserializeOwned;
use std::path::Path;


pub fn load_file<Document: DeserializeOwned>(path: &Path) -> Result<Document, ConfigError> {
    let text = read_file(path)?;
    parse_document(&text, &path.display().to_string())
}


pub fn load_platform(path: &Path) -> Result<PlatformConfig, ConfigError> {
    load_file(path)
}


pub fn load_module(path: &Path) -> Result<ModuleConfig, ConfigError> {
    check_module_tenant(load_file(path)?, &path.display().to_string())
}


pub const TENANT_RESERVED: &str = "reserved name";


pub const TENANT_GRAMMAR: &str = "not a valid tenant name";


/// The single point every module `tenant` goes through: a reserved or grammar-invalid name is refused.
pub fn check_module_tenant(module: ModuleConfig, file: &str) -> Result<ModuleConfig, ConfigError> {
    let refusal = module.tenant.as_deref().and_then(|tenant| {
        if is_reserved_tenant(tenant) {
            Some(TENANT_RESERVED)
        } else if is_valid_tenant_grammar(tenant) {
            None
        } else {
            Some(TENANT_GRAMMAR)
        }
    });
    match refusal {
        Some(reason) => Err(ConfigError::Tenant {
            file: file.to_owned(),
            reason,
        }),
        None => Ok(module),
    }
}


/// Loads a tenant file merged over a common base; errors of the merged result name the tenant file and position in the merged document.
pub fn load_layered<Document: DeserializeOwned>(base: &Path, tenant: &Path) -> Result<Document, ConfigError> {
    let base_file = base.display().to_string();
    let tenant_file = tenant.display().to_string();
    let merged = merge_documents(&read_file(base)?, &base_file, &read_file(tenant)?, &tenant_file)?;
    parse_document(&merged, &format!("{tenant_file} (merged over {base_file})"))
}


pub fn load_module_for_tenant(base: &Path, tenant: &Path) -> Result<ModuleConfig, ConfigError> {
    check_module_tenant(load_layered(base, tenant)?, &tenant.display().to_string())
}
