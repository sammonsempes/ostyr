use crate::error::RenderError;
use crate::extensions::{Browser, Extension, ExtensionAction, ExtensionPolicy};
use crate::model::{Action, Mode};
use crate::types::ExtensionSettings;
use serde_json::{json, Map, Value};


pub const WILDCARD: &str = "*";


pub const SETTINGS_KEY: &str = "ExtensionSettings";


pub const POLICIES_KEY: &str = "policies";


pub fn default_mode(action: Action) -> &'static str {
    match action {
        Action::Allow => "allowed",
        Action::Block => "blocked",
    }
}


pub fn entry_mode(action: ExtensionAction) -> &'static str {
    match action {
        ExtensionAction::Allow => "allowed",
        ExtensionAction::Block => "blocked",
        ExtensionAction::Force => "force_installed",
    }
}


/// Chromium names the URL `update_url`, Firefox `install_url`.
pub fn url_key(browser: Browser) -> &'static str {
    match browser {
        Browser::Chromium => "update_url",
        Browser::Firefox => "install_url",
    }
}


pub fn entry(extension: &Extension) -> Value {
    let mut fields = Map::new();
    fields.insert("installation_mode".to_string(), json!(entry_mode(extension.action)));
    if let Some(url) = &extension.update_url {
        fields.insert(url_key(extension.browser).to_string(), json!(url));
    }
    Value::Object(fields)
}


/// Sorted keys (a `BTreeMap` collected in order), values built by `serde_json`: no string is concatenated into the document.
pub fn settings(policy: &ExtensionPolicy, browser: Browser) -> Value {
    let mut sorted = ExtensionSettings::new();
    sorted.insert(WILDCARD.to_string(), json!({"installation_mode": default_mode(policy.default)}));
    policy
        .extensions
        .iter()
        .filter(|extension| extension.browser == browser)
        .for_each(|extension| {
            sorted.insert(extension.id.clone(), entry(extension));
        });
    Value::Object(sorted.into_iter().collect())
}


pub fn render_chromium(policy: &ExtensionPolicy) -> Result<String, RenderError> {
    match policy.mode {
        Mode::Audit => Err(RenderError::AuditMode),
        Mode::Enforce => Ok(format!("{:#}\n", json!({ (SETTINGS_KEY): settings(policy, Browser::Chromium) }))),
    }
}


pub fn render_firefox(policy: &ExtensionPolicy) -> Result<String, RenderError> {
    match policy.mode {
        Mode::Audit => Err(RenderError::AuditMode),
        Mode::Enforce => Ok(format!(
            "{:#}\n",
            json!({ (POLICIES_KEY): { (SETTINGS_KEY): settings(policy, Browser::Firefox) } })
        )),
    }
}
