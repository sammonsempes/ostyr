use crate::error::WafError;
use crate::limits::MAX_JSON_BYTES;
use crate::model::Refusal;
use crate::render::render_reader;
use std::io::{Read, Write};


/// The report line of a refused route; a shadowed route names its owner.
pub fn refusal_line(refusal: &Refusal) -> String {
    let owner = refusal.shadowed_by.map_or_else(String::new, |index| format!(" {index}"));
    format!("route {} refused: {}{owner}", refusal.index, refusal.reason)
}


/// Writes the pretty JSON to `json` and one line per refused route to `report`.
pub fn render_to(input: &mut dyn Read, json: &mut dyn Write, report: &mut dyn Write) -> Result<usize, WafError> {
    render_to_capped(input, json, report, MAX_JSON_BYTES)
}


/// `render_to` that refuses, before writing anything, a configuration whose JSON exceeds `max_json_bytes`.
pub fn render_to_capped(input: &mut dyn Read, json: &mut dyn Write, report: &mut dyn Write, max_json_bytes: usize) -> Result<usize, WafError> {
    let rendered = render_reader(input)?;
    let encoded = serde_json::to_vec_pretty(&rendered.config)?;
    let bytes = encoded.len();
    if bytes > max_json_bytes {
        Err(WafError::OutputTooLarge { bytes, max: max_json_bytes })?;
    }
    json.write_all(&encoded)?;
    writeln!(json)?;
    rendered
        .refused
        .iter()
        .try_for_each(|refusal| writeln!(report, "{}", refusal_line(refusal)))?;
    Ok(rendered.refused.len())
}
