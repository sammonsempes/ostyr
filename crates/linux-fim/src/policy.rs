use crate::error::PolicyError;
use crate::limits::{NAMES_POLICY_PREFIX, POLICY_PREFIX};
use crate::model::{Ignore, Kprobe, KprobeArg, Limits, MatchArg, Metadata, Role, Selector, Spec, TracingPolicy, WatchKind};
use crate::types::SerializeFn;
use serde_saphyr::SerializeError;


pub const DOCUMENT_SEPARATOR: &str = "---\n";


pub const API_VERSION: &str = "cilium.io/v1alpha1";


pub const POLICY_KIND: &str = "TracingPolicy";


pub const HOOK_PERMISSION: &str = "security_file_permission";


pub const HOOK_PATH_TRUNCATE: &str = "security_path_truncate";


pub const HOOK_FILE_TRUNCATE: &str = "security_file_truncate";


pub const HOOK_MKNOD: &str = "security_path_mknod";


pub const HOOK_OPEN: &str = "security_file_open";


pub const HOOK_RENAME: &str = "security_path_rename";


pub const HOOK_SYMLINK: &str = "security_path_symlink";


pub const HOOK_LINK: &str = "security_path_link";


pub const HOOK_MMAP: &str = "security_mmap_file";


pub const HOOK_CHMOD: &str = "security_path_chmod";


pub const HOOK_CHOWN: &str = "security_path_chown";


pub const PROT_WRITE_MASK: &str = "2";


pub const MAP_SHARED_MASK: &str = "1";


pub const MAY_WRITE_MASK: &str = "2";


const OPERATOR_EQUAL: &str = "Equal";


const OPERATOR_PREFIX: &str = "Prefix";


const OPERATOR_MASK: &str = "Mask";


const TYPE_FILE: &str = "file";


const TYPE_PATH: &str = "path";


const TYPE_INT: &str = "int";


const TYPE_DENTRY: &str = "dentry";


const TYPE_UINT32: &str = "uint32";


const PATH_INDEX: u32 = 0;


const MODE_INDEX: u32 = 1;


const RENAME_TARGET_INDEX: u32 = 3;


const SYMLINK_NAME_INDEX: u32 = 1;


const LINK_EXISTING_INDEX: u32 = 0;


const LINK_CREATED_INDEX: u32 = 2;


const MMAP_PROT_INDEX: u32 = 1;


const MMAP_FLAGS_INDEX: u32 = 2;


const RENAME_SOURCE_INDEX: u32 = 2;


/// Renders the TracingPolicies of a role as YAML documents separated by `---`.
pub fn render_policy(role: &Role, limits: &Limits) -> Result<String, PolicyError> {
    render_with(role, limits, serde_saphyr::to_string::<TracingPolicy>)
}


/// Renders with an injected serialiser, so a test can make it fail.
pub fn render_with(role: &Role, limits: &Limits, serialize: SerializeFn) -> Result<String, PolicyError> {
    let documents = build_policies(role, limits)?
        .iter()
        .map(serialize)
        .collect::<Result<Vec<String>, SerializeError>>()?;
    Ok(documents.join(DOCUMENT_SEPARATOR))
}


/// The paths of a role by kind, each group refused when it exceeds what one Tetragon selector takes.
pub fn build_policies(role: &Role, limits: &Limits) -> Result<Vec<TracingPolicy>, PolicyError> {
    let files = paths_of(role, WatchKind::File);
    let prefixes = paths_of(role, WatchKind::Prefix);
    let tokens: Vec<String> = role.honeytokens.iter().map(|token| token.path.clone()).collect();
    let max = limits.max_selector_values;
    if files.is_empty() && prefixes.is_empty() && tokens.is_empty() {
        Err(PolicyError::Empty)
    } else if files.len() > max {
        Err(PolicyError::TooManyFiles { count: files.len(), max })
    } else if prefixes.len() > max {
        Err(PolicyError::TooManyPrefixes { count: prefixes.len(), max })
    } else if tokens.len() > max {
        Err(PolicyError::TooManyHoneytokens { count: tokens.len(), max })
    } else {
        Ok(vec![
            tracing_policy(policy_name(&role.name), content_kprobes(&files, &prefixes, &tokens)),
            tracing_policy(names_policy_name(&role.name), name_kprobes(&files, &prefixes, &tokens)),
        ])
    }
}


/// The paths of one kind in table order.
pub fn paths_of(role: &Role, kind: WatchKind) -> Vec<String> {
    role.watched
        .iter()
        .filter(|watched| watched.kind == kind)
        .map(|watched| watched.path.clone())
        .collect()
}


/// A policy of the Tetragon API version with the given kprobes.
pub fn tracing_policy(name: String, kprobes: Vec<Kprobe>) -> TracingPolicy {
    TracingPolicy {
        api_version: API_VERSION.to_string(),
        kind: POLICY_KIND.to_string(),
        metadata: Metadata { name },
        spec: Spec { kprobes },
    }
}


/// The name of the policy of a role that watches contents (writes, truncations, creations, mappings, opens).
pub fn policy_name(role_name: &str) -> String {
    format!("{POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that watches names (renames, links, permission changes); a different prefix, so no role name collides.
pub fn names_policy_name(role_name: &str) -> String {
    format!("{NAMES_POLICY_PREFIX}{role_name}")
}


/// Both policy names of a role, the ones `classify` matches exactly.
pub fn policy_names(role_name: &str) -> Vec<String> {
    vec![policy_name(role_name), names_policy_name(role_name)]
}


/// The kprobes on contents: writes, truncations, creations, shared writable mappings, opens of honeytokens (the split is explained in the crate notes).
pub fn content_kprobes(files: &[String], prefixes: &[String], tokens: &[String]) -> Vec<Kprobe> {
    let watching = !files.is_empty() || !prefixes.is_empty();
    let directories: Vec<String> = prefixes.iter().map(|prefix| directory_of(prefix)).collect();
    let write_mask = mask_arg(MODE_INDEX, MAY_WRITE_MASK);
    let mapping = [mask_arg(MMAP_PROT_INDEX, PROT_WRITE_MASK), mask_arg(MMAP_FLAGS_INDEX, MAP_SHARED_MASK)];
    let candidates = [
        (
            watching,
            kprobe(
                HOOK_PERMISSION,
                &[(0, TYPE_FILE), (1, TYPE_INT)],
                false,
                watch_selectors(PATH_INDEX, files, prefixes, &[write_mask]),
            ),
        ),
        (
            watching,
            kprobe(
                HOOK_PATH_TRUNCATE,
                &[(0, TYPE_PATH)],
                true,
                watch_selectors(PATH_INDEX, files, prefixes, &[]),
            ),
        ),
        (
            watching,
            kprobe(
                HOOK_FILE_TRUNCATE,
                &[(0, TYPE_FILE)],
                true,
                watch_selectors(PATH_INDEX, files, prefixes, &[]),
            ),
        ),
        (
            !prefixes.is_empty(),
            kprobe(HOOK_MKNOD, &[(0, TYPE_PATH)], false, watch_selectors(PATH_INDEX, &[], &directories, &[])),
        ),
        (
            !tokens.is_empty(),
            kprobe(HOOK_OPEN, &[(0, TYPE_FILE)], false, watch_selectors(PATH_INDEX, tokens, &[], &[])),
        ),
        (
            watching,
            kprobe(
                HOOK_MMAP,
                &[(0, TYPE_FILE), (MMAP_PROT_INDEX, TYPE_UINT32), (MMAP_FLAGS_INDEX, TYPE_UINT32)],
                false,
                watch_selectors(PATH_INDEX, files, prefixes, &mapping),
            ),
        ),
    ];
    candidates.into_iter().filter(|(wanted, _)| *wanted).map(|(_, probe)| probe).collect()
}


/// The kprobes on names: renames over, symlinks and hard links into, and permission changes of watched paths; hard links of honeytokens.
pub fn name_kprobes(files: &[String], prefixes: &[String], tokens: &[String]) -> Vec<Kprobe> {
    let watching = !files.is_empty() || !prefixes.is_empty();
    let candidates = [
        (
            watching,
            kprobe(
                HOOK_RENAME,
                &[(RENAME_SOURCE_INDEX, TYPE_PATH), (RENAME_TARGET_INDEX, TYPE_DENTRY)],
                false,
                watch_selectors(RENAME_TARGET_INDEX, files, prefixes, &[]),
            ),
        ),
        (
            watching,
            kprobe(
                HOOK_SYMLINK,
                &[(0, TYPE_PATH), (SYMLINK_NAME_INDEX, TYPE_DENTRY)],
                false,
                watch_selectors(SYMLINK_NAME_INDEX, files, prefixes, &[]),
            ),
        ),
        (
            watching || !tokens.is_empty(),
            kprobe(
                HOOK_LINK,
                &[(LINK_EXISTING_INDEX, TYPE_DENTRY), (LINK_CREATED_INDEX, TYPE_DENTRY)],
                false,
                link_selectors(files, prefixes, tokens),
            ),
        ),
        (
            watching,
            kprobe(HOOK_CHMOD, &[(0, TYPE_PATH)], false, watch_selectors(PATH_INDEX, files, prefixes, &[])),
        ),
        (
            watching,
            kprobe(HOOK_CHOWN, &[(0, TYPE_PATH)], false, watch_selectors(PATH_INDEX, files, prefixes, &[])),
        ),
    ];
    candidates.into_iter().filter(|(wanted, _)| *wanted).map(|(_, probe)| probe).collect()
}


/// A prefix without its trailing slash: `security_path_mknod` reports the directory a file is created in.
pub fn directory_of(prefix: &str) -> String {
    prefix.strip_suffix('/').unwrap_or(prefix).to_string()
}


/// A `Mask` match on one argument.
pub fn mask_arg(index: u32, mask: &str) -> MatchArg {
    MatchArg {
        index,
        operator: OPERATOR_MASK.to_string(),
        values: vec![mask.to_string()],
    }
}


/// One kprobe; each argument is an index and a type, in the order the event reports them.
pub fn kprobe(call: &str, arguments: &[(u32, &str)], call_not_found: bool, selectors: Vec<Selector>) -> Kprobe {
    let args = arguments
        .iter()
        .map(|(index, arg_type)| KprobeArg {
            index: *index,
            arg_type: (*arg_type).to_string(),
        })
        .collect();
    Kprobe {
        call: call.to_string(),
        syscall: false,
        args,
        ignore: Ignore { call_not_found },
        selectors,
    }
}


/// One selector for the exact paths and one for the prefixes, each only when it has values, each carrying the extra matches.
pub fn watch_selectors(index: u32, files: &[String], prefixes: &[String], extra: &[MatchArg]) -> Vec<Selector> {
    [(OPERATOR_EQUAL, files), (OPERATOR_PREFIX, prefixes)]
        .into_iter()
        .filter(|(_, values)| !values.is_empty())
        .map(|(operator, values)| {
            let path = MatchArg {
                index,
                operator: operator.to_string(),
                values: values.to_vec(),
            };
            Selector {
                match_args: std::iter::once(path).chain(extra.iter().cloned()).collect(),
            }
        })
        .collect()
}


/// The hard link selectors: an existing watched file or honeytoken linked, or a new name created under a watched prefix.
pub fn link_selectors(files: &[String], prefixes: &[String], tokens: &[String]) -> Vec<Selector> {
    let existing = watch_selectors(LINK_EXISTING_INDEX, files, &[], &[]);
    let honeytokens = watch_selectors(LINK_EXISTING_INDEX, tokens, &[], &[]);
    let created = watch_selectors(LINK_CREATED_INDEX, &[], prefixes, &[]);
    existing.into_iter().chain(honeytokens).chain(created).collect()
}
