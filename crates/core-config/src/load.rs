use crate::error::ConfigError;
use crate::merge::merge_documents;
use crate::model::{ModuleConfig, PlatformConfig};
use crate::parse::{parse_document, read_file};
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
    load_file(path)
}


/// Loads a tenant file merged over a common base; errors of the merged result name the tenant file and position in the merged document.
pub fn load_layered<Document: DeserializeOwned>(base: &Path, tenant: &Path) -> Result<Document, ConfigError> {
    let base_file = base.display().to_string();
    let tenant_file = tenant.display().to_string();
    let merged = merge_documents(&read_file(base)?, &base_file, &read_file(tenant)?, &tenant_file)?;
    parse_document(&merged, &format!("{tenant_file} (merged over {base_file})"))
}


pub fn load_module_for_tenant(base: &Path, tenant: &Path) -> Result<ModuleConfig, ConfigError> {
    load_layered(base, tenant)
}
