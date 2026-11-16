use crate::limits::{MAX_FIELD_BYTES, UNKNOWN_PROCESS};
use crate::model::FimEvent;
use crate::policy::{
    HOOK_CHMOD, HOOK_CHOWN, HOOK_FILE_TRUNCATE, HOOK_LINK, HOOK_MKNOD, HOOK_MMAP, HOOK_OPEN, HOOK_PATH_TRUNCATE, HOOK_PERMISSION, HOOK_RENAME,
    HOOK_SYMLINK,
};
use serde::Deserialize;


const NO_FUNCTION: &str = "";


const WRITE_HOOKS: &[(&str, usize)] = &[
    (HOOK_PERMISSION, 0),
    (HOOK_PATH_TRUNCATE, 0),
    (HOOK_FILE_TRUNCATE, 0),
    (HOOK_MKNOD, 0),
    (HOOK_MMAP, 0),
    (HOOK_CHMOD, 0),
    (HOOK_CHOWN, 0),
    (HOOK_RENAME, 1),
    (HOOK_SYMLINK, 1),
];


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


/// Maps one Tetragon export line to an event of one of the policies; over the hard cap, a line naming one is `Oversized`.
pub fn classify(line: &str, max_line_bytes: usize, policies: &[String]) -> Option<FimEvent> {
    if line.len() > max_line_bytes {
        oversized_of(line, policies)
    } else {
        match serde_json::from_str::<ExportLine>(line) {
            Ok(parsed) => parsed.process_kprobe.and_then(|kprobe| event_of(kprobe, policies)),
            Err(error) => {
                let reason = error.to_string();
                tracing::debug!(reason, "export line is not JSON of the expected shape");
                None
            }
        }
    }
}


/// The oversized event of the first policy whose exact `policy_name` member appears in the raw line.
pub fn oversized_of(line: &str, policies: &[String]) -> Option<FimEvent> {
    let bytes = line.len();
    policies
        .iter()
        .find(|policy| line.contains(&format!("\"policy_name\":\"{policy}\"")))
        .map(|policy| FimEvent::Oversized {
            policy: policy.clone(),
            bytes,
        })
}


/// The event of a kprobe of one of the policies, its path taken from the argument the hook names.
pub fn event_of(kprobe: ProcessKprobe, policies: &[String]) -> Option<FimEvent> {
    let ours = kprobe.policy_name.as_ref().is_some_and(|name| policies.contains(name));
    let function = kprobe.function_name.as_deref().unwrap_or(NO_FUNCTION);
    let process = kprobe
        .process
        .and_then(|info| info.binary)
        .map_or_else(|| UNKNOWN_PROCESS.to_string(), |binary| escape_field(&binary));
    let path_of = |position: usize| path_at(&kprobe.args, position);
    match (ours, function) {
        (false, _) => None,
        (true, HOOK_OPEN) => path_of(0).map(|path| FimEvent::Honeytoken { path, process }),
        (true, HOOK_LINK) => path_of(0)
            .zip(path_of(1))
            .map(|(existing, created)| FimEvent::Link { existing, created, process }),
        (true, hook) => WRITE_HOOKS
            .iter()
            .find(|(name, _)| *name == hook)
            .and_then(|(_, position)| path_of(*position))
            .map(|path| FimEvent::Write { path, process }),
    }
}


/// The escaped path of the argument at one position of the event.
pub fn path_at(args: &[KprobeValue], position: usize) -> Option<String> {
    args.get(position)
        .and_then(|value| value.file_arg.as_ref().or(value.path_arg.as_ref()))
        .and_then(|found| found.path.as_deref())
        .map(escape_field)
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
