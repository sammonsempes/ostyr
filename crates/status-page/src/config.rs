use crate::error::StatusPageError;
use crate::model::{Limits, PageConfig};
use core_config::load::load_file;
use std::collections::BTreeSet;
use std::path::Path;


pub fn check_text(field: &'static str, text: &str, limit: usize) -> Result<(), StatusPageError> {
    if text.len() > limit {
        Err(StatusPageError::TextTooLong { field, limit })
    } else {
        Ok(())
    }
}


pub fn check_count(what: &'static str, count: usize, limit: usize) -> Result<(), StatusPageError> {
    if count > limit {
        Err(StatusPageError::TooMany { what, limit })
    } else {
        Ok(())
    }
}


pub fn validate_config(config: &PageConfig, limits: &Limits) -> Result<(), StatusPageError> {
    let limit = limits.max_text_bytes;
    check_count("components", config.components.len(), limits.max_components)?;
    check_text("id", &config.id, limit)?;
    check_text("tenant", &config.tenant, limit)?;
    check_text("title", &config.title, limit)?;
    config.components.iter().try_for_each(|component| {
        check_text("component name", &component.name, limit).and_then(|()| check_text("service", &component.service, limit))
    })?;
    let services: BTreeSet<&str> = config.components.iter().map(|component| component.service.as_str()).collect();
    if services.len() == config.components.len() {
        Ok(())
    } else {
        Err(StatusPageError::DuplicateService)
    }
}


pub fn load_config(path: &Path, limits: &Limits) -> Result<PageConfig, StatusPageError> {
    let config: PageConfig = load_file(path)?;
    validate_config(&config, limits)?;
    Ok(config)
}
