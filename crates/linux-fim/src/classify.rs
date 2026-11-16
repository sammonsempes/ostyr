use crate::limits::{MAX_FIELD_BYTES, POLICY_PREFIX, UNKNOWN_PROCESS};
use crate::model::FimEvent;
use crate::policy::{HOOK_FILE_TRUNCATE, HOOK_MKNOD, HOOK_OPEN, HOOK_PATH_TRUNCATE, HOOK_PERMISSION};
use serde::Deserialize;


const NO_FUNCTION: &str = "";


#[derive(Debug, Deserialize)]
pub struct ExportLine {
    process_kprobe: Option<ProcessKprobe>,
}


#[derive(Debug, Deserialize)]
pub struct ProcessKprobe {
    policy_name: Option<String>,
    function_name: Option<String>,
    #[serde(default)]
    args: Vec<KprobeValue>,
    process: Option<ProcessInfo>,
}


#[derive(Debug, Deserialize)]
pub struct KprobeValue {
    file_arg: Option<PathValue>,
    path_arg: Option<PathValue>,
}


#[derive(Debug, Deserialize)]
pub struct PathValue {
    path: Option<String>,
}


#[derive(Debug, Deserialize)]
pub struct ProcessInfo {
    binary: Option<String>,
}


/// Maps one Tetragon export line to a file event of an Ostyr policy; `None` for anything else, an oversized line and invalid JSON included.
pub fn classify(line: &str, max_line_bytes: usize) -> Option<FimEvent> {
    if line.len() > max_line_bytes {
        let bytes = line.len();
        tracing::debug!(bytes, max_line_bytes, "export line over the cap");
        None
    } else {
        match serde_json::from_str::<ExportLine>(line) {
            Ok(parsed) => parsed.process_kprobe.and_then(event_of),
            Err(error) => {
                let reason = error.to_string();
                tracing::debug!(reason, "export line is not JSON of the expected shape");
                None
            }
        }
    }
}


/// The event of a kprobe of an Ostyr policy: an open of a honeytoken or a write, truncation or creation.
pub fn event_of(kprobe: ProcessKprobe) -> Option<FimEvent> {
    let ours = kprobe.policy_name.as_deref().is_some_and(|name| name.starts_with(POLICY_PREFIX));
    let function = kprobe.function_name.as_deref().unwrap_or(NO_FUNCTION);
    let found_path = kprobe
        .args
        .iter()
        .find_map(|value| {
            value
                .file_arg
                .as_ref()
                .or(value.path_arg.as_ref())
                .and_then(|found| found.path.as_deref())
        })
        .map(escape_field);
    let process = kprobe
        .process
        .and_then(|info| info.binary)
        .map_or_else(|| UNKNOWN_PROCESS.to_string(), |binary| escape_field(&binary));
    let is_write = [HOOK_PERMISSION, HOOK_PATH_TRUNCATE, HOOK_FILE_TRUNCATE, HOOK_MKNOD].contains(&function);
    match (ours, found_path) {
        (true, Some(path)) if function == HOOK_OPEN => Some(FimEvent::Honeytoken { path, process }),
        (true, Some(path)) if is_write => Some(FimEvent::Write { path, process }),
        _ => None,
    }
}


/// Escapes control characters and cuts the text at the field cap with a visible marker of the omitted bytes.
pub fn escape_field(text: &str) -> String {
    let escaped: String = text.chars().flat_map(escape_char).collect();
    if escaped.len() > MAX_FIELD_BYTES {
        let kept: String = escaped.chars().scan(0, keep_within_cap).collect();
        format!("{kept}[cut {} bytes]", escaped.len() - kept.len())
    } else {
        escaped
    }
}


/// A printable ASCII character other than the backslash as itself, any other character (control, bidirectional, non-ASCII) as its escape.
pub fn escape_char(character: char) -> Vec<char> {
    if (character.is_ascii_graphic() || character == ' ') && character != '\\' {
        vec![character]
    } else {
        character.escape_default().collect()
    }
}


/// Keeps a character while the running byte total stays within the field cap; the scan ends at the first character that does not fit.
pub fn keep_within_cap(used: &mut usize, character: char) -> Option<char> {
    *used += character.len_utf8();
    (*used <= MAX_FIELD_BYTES).then_some(character)
}
