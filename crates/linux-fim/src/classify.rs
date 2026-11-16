use crate::limits::{
    FULL_NAME_POLICY_PREFIX, FULL_SOURCE_POLICY_PREFIX, FULL_TARGET_POLICY_PREFIX, MAX_FIELD_BYTES, MAX_KPROBE_ARGS, REVERSED_ANCESTOR_POLICY_PREFIX,
    REVERSED_NAMES_POLICY_PREFIX, REVERSED_TOKEN_POLICY_PREFIX, TOKEN_POLICY_PREFIX, UNKNOWN_PROCESS, UNRESOLVED_NAME,
};
use crate::model::{FimEvent, WatchSets};
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


const SECOND_PAIR: usize = 2;


const LINK_REVERSED_EXISTING: usize = 2;


const FULL_PREFIXES: &[&str] = &[FULL_SOURCE_POLICY_PREFIX, FULL_TARGET_POLICY_PREFIX, FULL_NAME_POLICY_PREFIX];


const TOKEN_PREFIXES: &[&str] = &[TOKEN_POLICY_PREFIX, REVERSED_TOKEN_POLICY_PREFIX];


const TARGET_FIRST_RENAME_PREFIXES: &[&str] = &[
    REVERSED_NAMES_POLICY_PREFIX,
    REVERSED_ANCESTOR_POLICY_PREFIX,
    REVERSED_TOKEN_POLICY_PREFIX,
    FULL_TARGET_POLICY_PREFIX,
];


const CREATED_FIRST_LINK_PREFIXES: &[&str] = &[REVERSED_NAMES_POLICY_PREFIX, REVERSED_TOKEN_POLICY_PREFIX, FULL_NAME_POLICY_PREFIX];


const LINK_FORWARD_CREATED: usize = 2;


const SPLIT_HOOKS: &[&str] = &[HOOK_UNLINK, HOOK_RMDIR, HOOK_SYMLINK];


const NAME_MATCH_HOOKS: &[&str] = &[HOOK_SETXATTR, HOOK_REMOVEXATTR, HOOK_SET_ACL, HOOK_REMOVE_ACL];


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


/// Maps an export line to an event of one of the policies (`sets`: the declared paths); a line over the caps is `Oversized`.
pub fn classify(line: &str, max_line_bytes: usize, policies: &[String], sets: &WatchSets) -> Option<FimEvent> {
    if line.len() > max_line_bytes || arg_count(line) > MAX_KPROBE_ARGS {
        oversized_of(line, policies)
    } else {
        match serde_json::from_str::<ExportLine>(line) {
            Ok(parsed) => parsed.process_kprobe.and_then(|kprobe| event_of(kprobe, policies, sets)),
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
pub fn event_of(kprobe: ProcessKprobe, policies: &[String], sets: &WatchSets) -> Option<FimEvent> {
    let ours = kprobe.policy_name.as_ref().is_some_and(|name| policies.contains(name));
    let function = kprobe.function_name.as_deref().unwrap_or(NO_FUNCTION);
    let process = kprobe
        .process
        .and_then(|info| info.binary)
        .map_or_else(|| UNKNOWN_PROCESS.to_string(), |binary| escape_field(&binary));
    let policy = kprobe.policy_name.as_deref().unwrap_or(NO_FUNCTION);
    let token_policy = has_prefix(policy, TOKEN_PREFIXES);
    let full = has_prefix(policy, FULL_PREFIXES);
    let severity = token_policy || full;
    let args = &kprobe.args;
    let first = pair_of(0, full);
    match (ours, function, severity) {
        (false, _, _) => None,
        (true, HOOK_OPEN, _) => Some(honeytoken_of(path_at(args, 0), policy, function, &process)),
        (true, HOOK_UNLINK | HOOK_RMDIR, true) => Some(removal_of(real_at(args, first, sets), token_policy, policy, function, &process, sets)),
        (true, HOOK_LINK, _) => {
            let (existing, created) = if has_prefix(policy, CREATED_FIRST_LINK_PREFIXES) {
                (name_at(args, LINK_REVERSED_EXISTING), real_name(args, first, sets))
            } else {
                (name_at(args, 0), real_name(args, (1, LINK_FORWARD_CREATED), sets))
            };
            let honeytoken = severity && (is_token_side(&existing, token_policy, true, sets) || is_token_side(&created, token_policy, false, sets));
            Some(FimEvent::Link {
                existing,
                created,
                process,
                honeytoken,
                name_match: !has_prefix(policy, CREATED_FIRST_LINK_PREFIXES),
            })
        }
        (true, HOOK_RENAME, _) => {
            let first_side = real_name(args, first, sets);
            let second_side = real_name(args, pair_of(SECOND_PAIR, full), sets);
            let (source, target) = if has_prefix(policy, TARGET_FIRST_RENAME_PREFIXES) {
                (second_side, first_side)
            } else {
                (first_side, second_side)
            };
            let honeytoken = severity && (is_token_side(&source, token_policy, false, sets) || is_token_side(&target, token_policy, false, sets));
            Some(FimEvent::Rename {
                source,
                target,
                process,
                honeytoken,
            })
        }
        (true, hook, _) => WRITE_HOOKS.contains(&hook).then(|| {
            let found = if SPLIT_HOOKS.contains(&hook) {
                real_at(args, first, sets)
            } else {
                path_at(args, 0)
            };
            found.map_or_else(
                || missing_path(policy, hook, &process),
                |path| FimEvent::Write {
                    path,
                    process: process.clone(),
                    name_match: NAME_MATCH_HOOKS.contains(&hook),
                },
            )
        }),
    }
}


/// Whether the policy name starts with one of the prefixes.
pub fn has_prefix(policy: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| policy.starts_with(prefix))
}


/// The positions (directory, name) of the pair that starts at `position`: a full-path policy lists the dentry first.
pub fn pair_of(position: usize, full: bool) -> (usize, usize) {
    if full {
        (position + 1, position)
    } else {
        (position, position + 1)
    }
}


/// A removal in a honeytoken or full-path policy: a honeytoken when it names a declared one, else a write (by name only in a honeytoken policy).
pub fn removal_of(found: Option<String>, token_policy: bool, policy: &str, function: &str, process: &str, sets: &WatchSets) -> FimEvent {
    found.map_or_else(
        || missing_path(policy, function, process),
        |path| {
            if is_token_side(&path, false, false, sets) {
                FimEvent::Honeytoken {
                    path,
                    process: process.to_string(),
                }
            } else {
                FimEvent::Write {
                    path,
                    process: process.to_string(),
                    name_match: token_policy,
                }
            }
        },
    )
}


/// Whether a path is a declared honeytoken or a directory above one (`trust_unresolved`: the marker counts; `by_name`: a token path may end with it).
pub fn is_token_side(side: &str, trust_unresolved: bool, by_name: bool, sets: &WatchSets) -> bool {
    let candidates = sets.tokens.iter().chain(sets.token_ancestors.iter());
    (trust_unresolved && side == UNRESOLVED_NAME)
        || candidates
            .into_iter()
            .any(|token| token == side || (by_name && side.len() > 1 && token.ends_with(side)))
}


/// Whether a path is declared in the role: a watched file, a honeytoken, a directory above them, or under a prefix.
pub fn declared(path: &str, sets: &WatchSets) -> bool {
    [&sets.files, &sets.tokens, &sets.ancestors, &sets.token_ancestors]
        .iter()
        .any(|group| group.iter().any(|declared_path| declared_path == path))
        || sets.prefixes.iter().any(|prefix| path.starts_with(prefix.as_str()))
}


/// A honeytoken event, or the missing-path event when the path is absent.
pub fn honeytoken_of(found: Option<String>, policy: &str, function: &str, process: &str) -> FimEvent {
    found.map_or_else(
        || missing_path(policy, function, process),
        |path| FimEvent::Honeytoken {
            path,
            process: process.to_string(),
        },
    )
}


/// The event of a content or removal hook whose path argument is missing: logged and returned, so the caller counts it, never dropped.
pub fn missing_path(policy: &str, function: &str, process: &str) -> FimEvent {
    tracing::warn!(policy, function, "kprobe event without a path argument");
    FimEvent::MissingPath {
        policy: policy.to_string(),
        function: function.to_string(),
        process: process.to_string(),
    }
}


/// The escaped path of a name argument, or the visible unresolved marker when Tetragon could not resolve it (a very deep or odd chain).
pub fn name_at(args: &[KprobeValue], position: usize) -> String {
    path_at(args, position).unwrap_or_else(|| UNRESOLVED_NAME.to_string())
}


/// The escaped path of the argument at one position of the event.
pub fn path_at(args: &[KprobeValue], position: usize) -> Option<String> {
    raw_at(args, position).map(escape_field)
}


/// The path of the argument at one position, as Tetragon wrote it.
pub fn raw_at(args: &[KprobeValue], position: usize) -> Option<&str> {
    args.get(position)
        .and_then(|value| value.file_arg.as_ref().or(value.path_arg.as_ref()))
        .and_then(|found| found.path.as_deref())
}


/// The directory path followed by the final component of the dentry argument: a dentry alone stops at its mount root.
pub fn joined_raw(args: &[KprobeValue], (directory, name): (usize, usize)) -> Option<String> {
    let parent = raw_at(args, directory)?;
    let leaf = raw_at(args, name)?.rsplit('/').next().filter(|part| !part.is_empty())?;
    Some(format!("{}/{leaf}", parent.trim_end_matches('/')))
}


/// The escaped real path of a pair: the joined path when declared, else the declared dentry path (a bind mount), else the joined path.
pub fn real_at(args: &[KprobeValue], pair: (usize, usize), sets: &WatchSets) -> Option<String> {
    let joined = joined_raw(args, pair);
    let dentry = raw_at(args, pair.1).filter(|path| declared(path, sets)).map(str::to_string);
    joined
        .clone()
        .filter(|path| declared(path, sets))
        .or(dentry)
        .or(joined)
        .map(|path| escape_field(&path))
}


/// The real path of a pair, or the visible unresolved marker.
pub fn real_name(args: &[KprobeValue], pair: (usize, usize), sets: &WatchSets) -> String {
    real_at(args, pair, sets).unwrap_or_else(|| UNRESOLVED_NAME.to_string())
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
