use crate::caddy::CaddyConfig;
use crate::cadir::{ca_root_path, write_ca_root};
use crate::error::WafError;
use crate::limits::MAX_JSON_BYTES;
use crate::model::Refusal;
use crate::render::render_reader;
use std::io::{Read, Write};
use std::path::Path;


/// The report line of a refused route; a shadowed route names its owner.
pub fn refusal_line(refusal: &Refusal) -> String {
    let owner = refusal.shadowed_by.map_or_else(String::new, |index| format!(" {index}"));
    format!("route {} refused: {}{owner}", refusal.index, refusal.reason)
}


/// Points every issuer that trusts a private root at `path`, the file written from the checked bytes.
pub fn place_ca_root(config: &mut CaddyConfig, path: Option<&str>) {
    let policies = config.apps.tls.iter_mut().flat_map(|app| app.automation.policies.iter_mut());
    policies
        .flat_map(|policy| policy.issuers.iter_mut())
        .filter(|issuer| !issuer.trusted_roots_pem_files.is_empty())
        .for_each(|issuer| issuer.trusted_roots_pem_files = path.iter().map(|value| value.to_string()).collect());
}


/// Writes the pretty JSON to `json`, one line per refused route to `report`, and the checked CA root file, if any, into `out_dir`.
pub fn render_to(input: &mut dyn Read, json: &mut dyn Write, report: &mut dyn Write, out_dir: &Path) -> Result<usize, WafError> {
    render_to_capped(input, json, report, out_dir, MAX_JSON_BYTES)
}


/// `render_to` that refuses, before writing anything, a configuration whose JSON exceeds `max_json_bytes`.
pub fn render_to_capped(
    input: &mut dyn Read,
    json: &mut dyn Write,
    report: &mut dyn Write,
    out_dir: &Path,
    max_json_bytes: usize,
) -> Result<usize, WafError> {
    let mut rendered = render_reader(input)?;
    let root_path = rendered.ca_root.as_ref().map(|root| ca_root_path(out_dir, root)).transpose()?;
    place_ca_root(&mut rendered.config, root_path.as_deref());
    let encoded = serde_json::to_vec_pretty(&rendered.config)?;
    let bytes = encoded.len();
    if bytes > max_json_bytes {
        Err(WafError::OutputTooLarge { bytes, max: max_json_bytes })?;
    }
    rendered.ca_root.as_ref().map(|root| write_ca_root(out_dir, root)).transpose()?;
    json.write_all(&encoded)?;
    writeln!(json)?;
    rendered
        .refused
        .iter()
        .try_for_each(|refusal| writeln!(report, "{}", refusal_line(refusal)))?;
    Ok(rendered.refused.len())
}
