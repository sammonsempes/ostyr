use crate::error::StatusPageError;
use crate::model::{ComponentConfig, ComponentState, Limits, PageConfig, RuleConfig};
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


pub fn rule_error(component: &ComponentConfig, reason: &'static str) -> StatusPageError {
    StatusPageError::InvalidRule {
        service: component.service.clone(),
        reason,
    }
}


pub fn validate_rule(config: &PageConfig, component: &ComponentConfig, rule: &RuleConfig, limits: &Limits) -> Result<(), StatusPageError> {
    check_count("declared checks", config.checks.len(), limits.max_components)?;
    check_count("rule checks", rule.checks.len(), limits.max_components)?;
    config
        .checks
        .iter()
        .try_for_each(|check| check_text("check id", check, limits.max_text_bytes))?;
    if rule.checks.is_empty() {
        Err(rule_error(component, "no check"))
    } else if rule.checks.iter().any(|check| !config.checks.contains(check)) {
        Err(rule_error(component, "unknown check id"))
    } else if rule.degraded_after == 0 || rule.down_after == 0 || rule.recover_after == 0 || rule.window_seconds == 0 {
        Err(rule_error(component, "zero count"))
    } else if rule.degraded_after > rule.down_after {
        Err(rule_error(component, "degraded_after above down_after"))
    } else if rule.unknown_state == Some(ComponentState::Operational) {
        Err(rule_error(component, "unknown shown as operational"))
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
    config.components.iter().try_for_each(|component| {
        component
            .rule
            .as_ref()
            .map_or(Ok(()), |rule| validate_rule(config, component, rule, limits))
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
