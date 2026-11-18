use grc::regulatory::{build_regulatory, load_incident, render_drafts, to_json};
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


const USAGE: &str = "usage: grc_regulatory <incident-file> --now <RFC 3339> [--format markdown|json] [--out <path>]";


const NOW_FLAG: &str = "--now";


const FORMAT_FLAG: &str = "--format";


const OUT_FLAG: &str = "--out";


const INCIDENT_ARGUMENT: usize = 1;


fn flag_value<'a>(arguments: &'a [String], flag: &str) -> Option<&'a str> {
    arguments
        .iter()
        .position(|text| text == flag)
        .and_then(|position| arguments.get(position + 1))
        .map(String::as_str)
}


fn write_output(out: Option<&str>, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    match out {
        Some(path) => {
            let target = Path::new(path);
            let directory = target.parent().filter(|parent| !parent.as_os_str().is_empty()).unwrap_or(Path::new("."));
            let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
            temporary.write_all(bytes)?;
            temporary.persist(target)?;
        }
        None => stdout().write_all(bytes)?,
    }
    Ok(())
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().collect();
    let incident_path = arguments.get(INCIDENT_ARGUMENT).ok_or(USAGE)?;
    let now = OffsetDateTime::parse(flag_value(&arguments, NOW_FLAG).ok_or(USAGE)?, &Rfc3339)?;
    let incident = load_incident(Path::new(incident_path))?;
    let mut rendered = Vec::new();
    match flag_value(&arguments, FORMAT_FLAG).unwrap_or("markdown") {
        "markdown" => rendered.extend_from_slice(render_drafts(&incident, now)?.as_bytes()),
        "json" => to_json(&build_regulatory(&incident, now)?, &mut rendered)?,
        _ => Err(USAGE)?,
    }
    write_output(flag_value(&arguments, OUT_FLAG), &rendered)
}
