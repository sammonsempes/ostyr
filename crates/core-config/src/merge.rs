use crate::error::ConfigError;
use crate::parse::parse_document;
use serde_json::Value;


/// Merges the overlay over the base (RFC 7396 JSON Merge Patch) and returns the result as pretty JSON, which is valid YAML.
pub fn merge_documents(base_text: &str, base_file: &str, overlay_text: &str, overlay_file: &str) -> Result<String, ConfigError> {
    let mut merged: Value = parse_document(base_text, base_file)?;
    let overlay: Value = parse_document(overlay_text, overlay_file)?;
    json_patch::merge(&mut merged, &overlay);
    Ok(format!("{merged:#}"))
}
