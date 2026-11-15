use crate::error::WafError;
use crate::render::render_reader;
use std::io::{Read, Write};


/// Writes the pretty JSON to `json` and one line per refused route to `report`.
pub fn render_to(input: &mut dyn Read, json: &mut dyn Write, report: &mut dyn Write) -> Result<usize, WafError> {
    let rendered = render_reader(input)?;
    serde_json::to_writer_pretty(&mut *json, &rendered.config)?;
    writeln!(json)?;
    rendered
        .refused
        .iter()
        .try_for_each(|refusal| writeln!(report, "route {} refused: {}", refusal.index, refusal.reason))?;
    Ok(rendered.refused.len())
}
