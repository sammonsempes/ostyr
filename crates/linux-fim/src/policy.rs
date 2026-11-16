use crate::error::PolicyError;
use crate::limits::POLICY_PREFIX;
use crate::model::{Ignore, Kprobe, KprobeArg, Limits, MatchArg, Metadata, Role, Selector, Spec, TracingPolicy, WatchKind};
use crate::types::SerializeFn;


pub const API_VERSION: &str = "cilium.io/v1alpha1";


pub const POLICY_KIND: &str = "TracingPolicy";


pub const HOOK_PERMISSION: &str = "security_file_permission";


pub const HOOK_PATH_TRUNCATE: &str = "security_path_truncate";


pub const HOOK_FILE_TRUNCATE: &str = "security_file_truncate";


pub const HOOK_MKNOD: &str = "security_path_mknod";


pub const HOOK_OPEN: &str = "security_file_open";


pub const MAY_WRITE_MASK: &str = "2";


const OPERATOR_EQUAL: &str = "Equal";


const OPERATOR_PREFIX: &str = "Prefix";


const OPERATOR_MASK: &str = "Mask";


const TYPE_FILE: &str = "file";


const TYPE_PATH: &str = "path";


const TYPE_INT: &str = "int";


const PATH_INDEX: u32 = 0;


const MODE_INDEX: u32 = 1;


/// Renders the TracingPolicy of a role as YAML.
pub fn render_policy(role: &Role, limits: &Limits) -> Result<String, PolicyError> {
    render_with(role, limits, serde_saphyr::to_string::<TracingPolicy>)
}


/// Renders with an injected serialiser, so a test can make it fail.
pub fn render_with(role: &Role, limits: &Limits, serialize: SerializeFn) -> Result<String, PolicyError> {
    let policy = build_policy(role, limits)?;
    Ok(serialize(&policy)?)
}


/// The paths of a role by kind, each group refused when it exceeds what one Tetragon selector takes.
pub fn build_policy(role: &Role, limits: &Limits) -> Result<TracingPolicy, PolicyError> {
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
        Ok(TracingPolicy {
            api_version: API_VERSION.to_string(),
            kind: POLICY_KIND.to_string(),
            metadata: Metadata {
                name: format!("{POLICY_PREFIX}{}", role.name),
            },
            spec: Spec {
                kprobes: kprobes_of(&files, &prefixes, &tokens),
            },
        })
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


/// Every kprobe the role needs: writes and truncations of watched paths, creations under watched prefixes, opens of honeytokens.
pub fn kprobes_of(files: &[String], prefixes: &[String], tokens: &[String]) -> Vec<Kprobe> {
    let watching = !files.is_empty() || !prefixes.is_empty();
    let mask = MatchArg {
        index: MODE_INDEX,
        operator: OPERATOR_MASK.to_string(),
        values: vec![MAY_WRITE_MASK.to_string()],
    };
    let directories: Vec<String> = prefixes.iter().map(|prefix| directory_of(prefix)).collect();
    let candidates = [
        (
            watching,
            kprobe(
                HOOK_PERMISSION,
                &[TYPE_FILE, TYPE_INT],
                false,
                watch_selectors(files, prefixes, Some(&mask)),
            ),
        ),
        (
            watching,
            kprobe(HOOK_PATH_TRUNCATE, &[TYPE_PATH], true, watch_selectors(files, prefixes, None)),
        ),
        (
            watching,
            kprobe(HOOK_FILE_TRUNCATE, &[TYPE_FILE], true, watch_selectors(files, prefixes, None)),
        ),
        (
            !prefixes.is_empty(),
            kprobe(HOOK_MKNOD, &[TYPE_PATH], false, watch_selectors(&[], &directories, None)),
        ),
        (
            !tokens.is_empty(),
            kprobe(HOOK_OPEN, &[TYPE_FILE], false, watch_selectors(tokens, &[], None)),
        ),
    ];
    candidates.into_iter().filter(|(wanted, _)| *wanted).map(|(_, probe)| probe).collect()
}


/// A prefix without its trailing slash: `security_path_mknod` reports the directory a file is created in.
pub fn directory_of(prefix: &str) -> String {
    prefix.strip_suffix('/').unwrap_or(prefix).to_string()
}


/// One kprobe; argument indexes follow the order of the types.
pub fn kprobe(call: &str, types: &[&str], call_not_found: bool, selectors: Vec<Selector>) -> Kprobe {
    let args = (0..)
        .zip(types)
        .map(|(index, arg_type)| KprobeArg {
            index,
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


/// One selector for the exact paths and one for the prefixes, each only when it has values, each carrying the extra match.
pub fn watch_selectors(files: &[String], prefixes: &[String], extra: Option<&MatchArg>) -> Vec<Selector> {
    [(OPERATOR_EQUAL, files), (OPERATOR_PREFIX, prefixes)]
        .into_iter()
        .filter(|(_, values)| !values.is_empty())
        .map(|(operator, values)| {
            let path = MatchArg {
                index: PATH_INDEX,
                operator: operator.to_string(),
                values: values.to_vec(),
            };
            Selector {
                match_args: std::iter::once(path).chain(extra.cloned()).collect(),
            }
        })
        .collect()
}
