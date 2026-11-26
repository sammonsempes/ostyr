use crate::limits::{
    FOREIGN_FULL_NAME_POLICY_PREFIX, FOREIGN_FULL_SOURCE_POLICY_PREFIX, FOREIGN_FULL_TARGET_POLICY_PREFIX, FOREIGN_OPEN_POLICY_PREFIX,
    FOREIGN_REVERSED_TOKEN_POLICY_PREFIX, FOREIGN_TOKEN_POLICY_PREFIX, FULL_NAME_POLICY_PREFIX, FULL_SOURCE_POLICY_PREFIX, FULL_TARGET_POLICY_PREFIX,
    MAX_FIELD_BYTES, MAX_KPROBE_ARGS, POLICY_PREFIX, REVERSED_ANCESTOR_POLICY_PREFIX, REVERSED_NAMES_POLICY_PREFIX, REVERSED_TOKEN_POLICY_PREFIX,
    TOKEN_POLICY_PREFIX, UNKNOWN_PROCESS, UNRESOLVED_NAME, USER_FULL_NAME_POLICY_PREFIX, USER_FULL_SOURCE_POLICY_PREFIX,
    USER_FULL_TARGET_POLICY_PREFIX, USER_OPEN_POLICY_PREFIX, USER_REVERSED_TOKEN_POLICY_PREFIX, USER_TOKEN_POLICY_PREFIX,
};
use crate::model::{FimEvent, WatchSets};
use crate::policy::{
    HOOK_CHMOD, HOOK_CHOWN, HOOK_FILE_TRUNCATE, HOOK_LINK, HOOK_MKNOD, HOOK_MMAP, HOOK_OPEN, HOOK_PATH_TRUNCATE, HOOK_PERMISSION, HOOK_REMOVEXATTR,
    HOOK_REMOVE_ACL, HOOK_RENAME, HOOK_RMDIR, HOOK_SETXATTR, HOOK_SET_ACL, HOOK_SYMLINK, HOOK_UNLINK,
};
use crate::types::Identity;
use serde::de::IgnoredAny;
use serde::Deserialize;


const FOREIGN_TWINS: &[(&str, &str)] = &[
    (FOREIGN_OPEN_POLICY_PREFIX, POLICY_PREFIX),
    (FOREIGN_TOKEN_POLICY_PREFIX, TOKEN_POLICY_PREFIX),
    (FOREIGN_REVERSED_TOKEN_POLICY_PREFIX, REVERSED_TOKEN_POLICY_PREFIX),
    (FOREIGN_FULL_SOURCE_POLICY_PREFIX, FULL_SOURCE_POLICY_PREFIX),
    (FOREIGN_FULL_TARGET_POLICY_PREFIX, FULL_TARGET_POLICY_PREFIX),
    (FOREIGN_FULL_NAME_POLICY_PREFIX, FULL_NAME_POLICY_PREFIX),
    (USER_OPEN_POLICY_PREFIX, POLICY_PREFIX),
    (USER_TOKEN_POLICY_PREFIX, TOKEN_POLICY_PREFIX),
    (USER_REVERSED_TOKEN_POLICY_PREFIX, REVERSED_TOKEN_POLICY_PREFIX),
    (USER_FULL_SOURCE_POLICY_PREFIX, FULL_SOURCE_POLICY_PREFIX),
    (USER_FULL_TARGET_POLICY_PREFIX, FULL_TARGET_POLICY_PREFIX),
    (USER_FULL_NAME_POLICY_PREFIX, FULL_NAME_POLICY_PREFIX),
];


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


const CONTENT_HOOKS: &[&str] = &[HOOK_PERMISSION, HOOK_PATH_TRUNCATE, HOOK_FILE_TRUNCATE, HOOK_MMAP];


const SECOND_PAIR: usize = 2;


const SECOND_NAME: usize = 2;


const IDENTITY_ARGS: usize = 2;


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
    size_arg: Option<String>,
    uint_arg: Option<u32>,
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


/// Whether the line is a content hook (write, truncate, shared mapping) of the `fim-` policy of the role, the only one a package update explains.
pub fn content_line(line: &str, policies: &[String]) -> bool {
    serde_json::from_str::<ExportLine>(line)
        .ok()
        .and_then(|parsed| parsed.process_kprobe)
        .is_some_and(|kprobe| {
            let named = kprobe.policy_name.as_deref().unwrap_or(NO_FUNCTION);
            let function = kprobe.function_name.as_deref().unwrap_or(NO_FUNCTION);
            policies.iter().any(|policy| policy == named) && named.starts_with(POLICY_PREFIX) && CONTENT_HOOKS.contains(&function)
        })
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
    let identity = identity_of(&kprobe.args);
    let process = kprobe
        .process
        .and_then(|info| info.binary)
        .map_or_else(|| UNKNOWN_PROCESS.to_string(), |binary| escape_field(&binary));
    let (policy_text, foreign) = home_policy(kprobe.policy_name.as_deref().unwrap_or(NO_FUNCTION));
    let policy = policy_text.as_str();
    let token_policy = has_prefix(policy, TOKEN_PREFIXES);
    let full = has_prefix(policy, FULL_PREFIXES);
    let severity_policy = token_policy || full;
    let severity = severity_policy && !foreign;
    let args = &kprobe.args;
    let root = severity_policy.then_some(sets);
    let first = pair_of(0, full);
    match (ours, function, severity_policy) {
        (false, _, _) => None,
        (true, HOOK_OPEN, _) => Some(open_of(path_at(args, 0), (policy, function, &process), (sets, foreign, identity))),
        (true, HOOK_UNLINK | HOOK_RMDIR, true) => {
            let ambiguous = ambiguous_dentry(args, first, full, (sets, severity_policy));
            Some(removal_of(
                real_at(args, first, root),
                ambiguous,
                token_policy,
                (policy, function, &process),
                (sets, foreign, identity),
            ))
        }
        (true, HOOK_LINK, _) => {
            let created_first = has_prefix(policy, CREATED_FIRST_LINK_PREFIXES);
            let created_pair = if created_first { first } else { (1, LINK_FORWARD_CREATED) };
            let existing = name_at(args, if created_first { LINK_REVERSED_EXISTING } else { 0 });
            let (created, created_dentry) = side_of(args, created_pair, full, (sets, severity_policy));
            let hit = severity && created_dentry.is_none() && is_token_side(&created, token_policy, sets);
            let honeytoken = hit && is_planted(identity, &created, sets);
            Some(FimEvent::Link {
                existing,
                created,
                process,
                honeytoken,
                name_match: !created_first,
                foreign_mount_ns: foreign,
                mount_ambiguous: created_dentry.is_some() || (hit && !honeytoken),
                created_dentry,
            })
        }
        (true, HOOK_RENAME, _) => {
            let target_first = has_prefix(policy, TARGET_FIRST_RENAME_PREFIXES);
            let first_side = side_of(args, first, full, (sets, severity_policy));
            let second_side = if severity_policy {
                (name_at(args, SECOND_NAME), None)
            } else {
                side_of(args, pair_of(SECOND_PAIR, full), full, (sets, severity_policy))
            };
            let ((source, source_dentry), (target, target_dentry)) = if target_first {
                (second_side, first_side)
            } else {
                (first_side, second_side)
            };
            let source_hit = severity && source_dentry.is_none() && is_token_side(&source, token_policy, sets);
            let target_hit = severity && target_dentry.is_none() && is_token_side(&target, token_policy, sets);
            let matched_hit = if target_first { target_hit } else { source_hit };
            let matched_side = if target_first { &target } else { &source };
            let honeytoken = matched_hit && is_planted(identity, matched_side, sets);
            Some(FimEvent::Rename {
                source,
                target,
                process,
                honeytoken,
                foreign_mount_ns: foreign,
                mount_ambiguous: source_dentry.is_some() || target_dentry.is_some() || ((source_hit || target_hit) && !honeytoken),
                source_dentry,
                target_dentry,
            })
        }
        (true, hook, _) => WRITE_HOOKS.contains(&hook).then(|| {
            let split = SPLIT_HOOKS.contains(&hook);
            let found = if split { real_at(args, first, root) } else { path_at(args, 0) };
            let dentry_path = if split {
                ambiguous_dentry(args, first, full, (sets, severity_policy))
            } else {
                None
            };
            found.map_or_else(
                || missing_path(policy, hook, &process),
                |path| FimEvent::Write {
                    path,
                    process: process.clone(),
                    name_match: NAME_MATCH_HOOKS.contains(&hook),
                    foreign_mount_ns: foreign,
                    mount_ambiguous: dentry_path.is_some(),
                    dentry_path,
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


/// A removal in a honeytoken or full-path policy: a honeytoken only when it names a declared one by its real path, else a write.
pub fn removal_of(
    found: Option<String>,
    dentry_path: Option<String>,
    token_policy: bool,
    names: (&str, &str, &str),
    scope: (&WatchSets, bool, Option<Identity>),
) -> FimEvent {
    let (policy, function, process) = names;
    let (sets, foreign, identity) = scope;
    found.map_or_else(
        || missing_path(policy, function, process),
        |path| {
            let hit = !foreign && dentry_path.is_none() && is_token_side(&path, false, sets);
            if hit && is_planted(identity, &path, sets) {
                FimEvent::Honeytoken {
                    path,
                    process: process.to_string(),
                }
            } else {
                FimEvent::Write {
                    path,
                    process: process.to_string(),
                    name_match: token_policy,
                    foreign_mount_ns: foreign,
                    mount_ambiguous: dentry_path.is_some() || hit,
                    dentry_path,
                }
            }
        },
    )
}


/// Whether a path is a declared honeytoken or a directory above one (`trust_unresolved`: the unresolved marker counts).
pub fn is_token_side(side: &str, trust_unresolved: bool, sets: &WatchSets) -> bool {
    let candidates = sets.tokens.iter().chain(sets.token_ancestors.iter());
    (trust_unresolved && side == UNRESOLVED_NAME) || candidates.into_iter().any(|token| token == side)
}


/// Whether a path is declared in the role: a watched file, a honeytoken, a directory above them, or under a prefix.
pub fn declared(path: &str, sets: &WatchSets) -> bool {
    [&sets.files, &sets.tokens, &sets.ancestors, &sets.token_ancestors]
        .iter()
        .any(|group| group.iter().any(|declared_path| declared_path == path))
        || sets.prefixes.iter().any(|prefix| path.starts_with(prefix.as_str()))
}


/// The policy name a foreign twin stands for, and whether the policy is a foreign twin (it runs outside the host mount namespace).
pub fn home_policy(policy: &str) -> (String, bool) {
    FOREIGN_TWINS
        .iter()
        .find_map(|(foreign, home)| policy.strip_prefix(foreign).map(|role| (format!("{home}{role}"), true)))
        .unwrap_or_else(|| (policy.to_string(), false))
}


/// The open of a honeytoken: a `Honeytoken` only in the host namespaces with the identity of that token file, else a flagged `Write`.
pub fn open_of(found: Option<String>, names: (&str, &str, &str), scope: (&WatchSets, bool, Option<Identity>)) -> FimEvent {
    let (policy, function, process) = names;
    let (sets, foreign, identity) = scope;
    found.map_or_else(
        || missing_path(policy, function, process),
        |path| {
            if !foreign && sets.tokens.contains(&path) && is_planted(identity, &path, sets) {
                FimEvent::Honeytoken {
                    path,
                    process: process.to_string(),
                }
            } else {
                FimEvent::Write {
                    path,
                    process: process.to_string(),
                    name_match: false,
                    foreign_mount_ns: foreign,
                    mount_ambiguous: !foreign,
                    dentry_path: None,
                }
            }
        },
    )
}


/// Whether the event reached the file the plan planted at `path`: the (device, inode) equals the identity recorded for that very path, never another's.
pub fn is_planted(identity: Option<Identity>, path: &str, sets: &WatchSets) -> bool {
    identity.is_some_and(|(device, inode)| {
        sets.planted
            .iter()
            .any(|known| known.path == path && known.device == device && known.inode == inode)
    })
}


/// The (device, inode) the hook reports in its last two arguments (an unresolved one, as for a negative dentry, gives none).
pub fn identity_of(args: &[KprobeValue]) -> Option<Identity> {
    let first = args.len().checked_sub(IDENTITY_ARGS)?;
    let inode = args.get(first)?.size_arg.as_deref()?.parse::<u64>().ok()?;
    let device = args.get(first + 1)?.uint_arg?;
    Some((device, inode))
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


/// The directory path and the last dentry component; with `root`, a directory with no `path` is `/` when `/<leaf>` is declared.
pub fn joined_raw(args: &[KprobeValue], (directory, name): (usize, usize), root: Option<&WatchSets>) -> Option<String> {
    let leaf = raw_at(args, name)?.rsplit('/').next().filter(|part| !part.is_empty())?;
    let parent = raw_at(args, directory).or_else(|| root_parent(args, directory, leaf, root))?;
    Some(format!("{}/{leaf}", parent.trim_end_matches('/')))
}


/// `/` for a directory argument present with no path, when the policy proves it: the leaf under `/` is a declared path.
pub fn root_parent(args: &[KprobeValue], directory: usize, leaf: &str, root: Option<&WatchSets>) -> Option<&'static str> {
    let pathless = args
        .get(directory)
        .and_then(|value| value.file_arg.as_ref().or(value.path_arg.as_ref()))
        .is_some_and(|found| found.path.is_none());
    let candidate = format!("/{leaf}");
    let proven = root.is_some_and(|sets| declared(&candidate, sets));
    (pathless && proven).then_some("/")
}


/// The escaped joined path of a pair: the directory path and the last component of the dentry, never the dentry path alone.
pub fn real_at(args: &[KprobeValue], pair: (usize, usize), root: Option<&WatchSets>) -> Option<String> {
    joined_raw(args, pair, root).map(|path| escape_field(&path))
}


/// The real path of a pair, or the visible unresolved marker.
pub fn real_name(args: &[KprobeValue], pair: (usize, usize), root: Option<&WatchSets>) -> String {
    real_at(args, pair, root).unwrap_or_else(|| UNRESOLVED_NAME.to_string())
}


/// The escaped dentry path when the joined path is another, undeclared one (`scope`: the sets, and whether a missing root directory is proven).
pub fn ambiguous_dentry(args: &[KprobeValue], pair: (usize, usize), full: bool, scope: (&WatchSets, bool)) -> Option<String> {
    let (sets, rooted) = scope;
    joined_raw(args, pair, rooted.then_some(sets))
        .zip(raw_at(args, pair.1))
        .filter(|(joined, dentry)| full && joined != dentry && !declared(joined, sets) && declared(dentry, sets))
        .map(|(_, dentry)| escape_field(dentry))
}


/// The real path of a pair and its ambiguous dentry path, if any.
pub fn side_of(args: &[KprobeValue], pair: (usize, usize), full: bool, scope: (&WatchSets, bool)) -> (String, Option<String>) {
    let (sets, rooted) = scope;
    (real_name(args, pair, rooted.then_some(sets)), ambiguous_dentry(args, pair, full, scope))
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
