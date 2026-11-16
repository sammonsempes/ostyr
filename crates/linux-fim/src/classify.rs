use crate::limits::{MAX_FIELD_BYTES, MAX_KPROBE_ARGS, TOKEN_POLICY_PREFIX, UNKNOWN_PROCESS, UNRESOLVED_NAME};
use crate::model::FimEvent;
use crate::policy::{
    HOOK_CHMOD, HOOK_CHOWN, HOOK_FILE_TRUNCATE, HOOK_LINK, HOOK_MKNOD, HOOK_MMAP, HOOK_OPEN, HOOK_PATH_TRUNCATE, HOOK_PERMISSION, HOOK_REMOVEXATTR,
    HOOK_REMOVE_ACL, HOOK_RENAME, HOOK_RMDIR, HOOK_SETXATTR, HOOK_SET_ACL, HOOK_SYMLINK, HOOK_UNLINK,
};
use serde::de::IgnoredAny;
use serde::Deserialize;


const NO_FUNCTION: &str = "";


const WRITE_HOOKS: &[&str] = &[
    HOOK_PERMISSION,
    HOOK_PATH_TRUNCATE,
    HOOK_FILE_TRUNCATE,
    HOOK_MKNOD,
    HOOK_MMAP,
    HOOK_CHMOD,
    HOOK_CHOWN,
    HOOK_SYMLINK,
    HOOK_UNLINK,
    HOOK_RMDIR,
    HOOK_SETXATTR,
    HOOK_REMOVEXATTR,
    HOOK_SET_ACL,
    HOOK_REMOVE_ACL,
];


#[derive(Debug, Deserialize)]
pub struct CountedLine {
    process_kprobe: Option<CountedKprobe>,
}


#[derive(Debug, Deserialize)]
pub struct CountedKprobe {
    #[serde(default)]
    args: Vec<IgnoredAny>,
}


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


/// Maps one Tetragon export line to an event of one of the policies; a line over the hard cap or with too many arguments is `Oversized`.
pub fn classify(line: &str, max_line_bytes: usize, policies: &[String]) -> Option<FimEvent> {
    if line.len() > max_line_bytes || arg_count(line) > MAX_KPROBE_ARGS {
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


/// The number of kprobe arguments of a line, counted without keeping any of them (zero for a line that is not JSON of the shape).
pub fn arg_count(line: &str) -> usize {
    serde_json::from_str::<CountedLine>(line)
        .ok()
        .and_then(|counted| counted.process_kprobe)
        .map_or(0, |kprobe| kprobe.args.len())
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
    let token_policy = kprobe.policy_name.as_deref().is_some_and(|name| name.starts_with(TOKEN_POLICY_PREFIX));
    match (ours, function, token_policy) {
        (false, _, _) => None,
        (true, HOOK_OPEN, _) | (true, HOOK_UNLINK | HOOK_RMDIR, true) => path_of(0).map(|path| FimEvent::Honeytoken { path, process }),
        (true, HOOK_LINK, honeytoken) => Some(FimEvent::Link {
            existing: name_at(&kprobe.args, 0),
            created: name_at(&kprobe.args, 1),
            process,
            honeytoken,
        }),
        (true, HOOK_RENAME, honeytoken) => Some(FimEvent::Rename {
            source: name_at(&kprobe.args, 0),
            target: name_at(&kprobe.args, 1),
            process,
            honeytoken,
        }),
        (true, hook, _) => WRITE_HOOKS
            .contains(&hook)
            .then(|| path_of(0))
            .flatten()
            .map(|path| FimEvent::Write { path, process }),
    }
}


/// The escaped path of a name argument, or the visible unresolved marker when Tetragon could not resolve it (a very deep or odd chain).
pub fn name_at(args: &[KprobeValue], position: usize) -> String {
    path_at(args, position).unwrap_or_else(|| UNRESOLVED_NAME.to_string())
}


/// The escaped path of the argument at one position of the event.
pub fn path_at(args: &[KprobeValue], position: usize) -> Option<String> {
    args.get(position)
        .and_then(|value| value.file_arg.as_ref().or(value.path_arg.as_ref()))
        .and_then(|found| found.path.as_deref())
        .map(escape_field)
}


/// Escapes control characters and cuts the text at the field cap with a visible marker of the omitted bytes; never builds more than the cap.
pub fn escape_field(text: &str) -> String {
    let total: usize = text.chars().map(|character| escape_char(character).len()).sum();
    let kept: String = text.chars().flat_map(escape_char).scan(0, keep_within_cap).collect();
    if total > MAX_FIELD_BYTES {
        format!("{kept}[cut {} bytes]", total - kept.len())
    } else {
        kept
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
