use crate::error::PolicyError;
use crate::limits::{
    ANCESTOR_POLICY_PREFIX, ATTRIBUTE_POLICY_PREFIX, DELETE_POLICY_PREFIX, FOREIGN_FULL_NAME_POLICY_PREFIX, FOREIGN_FULL_SOURCE_POLICY_PREFIX,
    FOREIGN_FULL_TARGET_POLICY_PREFIX, FOREIGN_OPEN_POLICY_PREFIX, FOREIGN_REVERSED_TOKEN_POLICY_PREFIX, FOREIGN_TOKEN_POLICY_PREFIX,
    FULL_NAME_POLICY_PREFIX, FULL_SOURCE_POLICY_PREFIX, FULL_TARGET_POLICY_PREFIX, NAMES_POLICY_PREFIX, POLICY_PREFIX,
    REVERSED_ANCESTOR_POLICY_PREFIX, REVERSED_NAMES_POLICY_PREFIX, REVERSED_TOKEN_POLICY_PREFIX, TOKEN_POLICY_PREFIX, USER_FULL_NAME_POLICY_PREFIX,
    USER_FULL_SOURCE_POLICY_PREFIX, USER_FULL_TARGET_POLICY_PREFIX, USER_OPEN_POLICY_PREFIX, USER_REVERSED_TOKEN_POLICY_PREFIX,
    USER_TOKEN_POLICY_PREFIX,
};
use crate::model::{
    Ignore, Kprobe, KprobeArg, Limits, MatchArg, MatchNamespace, Metadata, Role, Selector, Spec, TokenOwner, TracingPolicy, WatchKind, WatchSets,
};
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


pub const HOOK_UNLINK: &str = "security_path_unlink";


pub const HOOK_RMDIR: &str = "security_path_rmdir";


pub const HOOK_SETXATTR: &str = "security_inode_setxattr";


pub const HOOK_REMOVEXATTR: &str = "security_inode_removexattr";


pub const HOOK_SET_ACL: &str = "security_inode_set_acl";


pub const HOOK_REMOVE_ACL: &str = "security_inode_remove_acl";


pub const MAP_SHARED_MASK: &str = "1";


pub const MAY_WRITE_MASK: &str = "2";


const OPERATOR_EQUAL: &str = "Equal";


const OPERATOR_PREFIX: &str = "Prefix";


const OPERATOR_MASK: &str = "Mask";


const OPERATOR_POSTFIX: &str = "Postfix";


const OPERATOR_IN: &str = "In";


const OPERATOR_NOT_IN: &str = "NotIn";


const NAMESPACE_MNT: &str = "Mnt";


const NAMESPACE_USER: &str = "User";


const HOST_BOTH: &[(&str, &str)] = &[(NAMESPACE_MNT, OPERATOR_IN), (NAMESPACE_USER, OPERATOR_IN)];


const FOREIGN_MOUNT: &[(&str, &str)] = &[(NAMESPACE_MNT, OPERATOR_NOT_IN)];


const FOREIGN_USER: &[(&str, &str)] = &[(NAMESPACE_MNT, OPERATOR_IN), (NAMESPACE_USER, OPERATOR_NOT_IN)];


const HOST_NAMESPACE: &str = "host_ns";


const TYPE_FILE: &str = "file";


const TYPE_PATH: &str = "path";


const TYPE_INT: &str = "int";


const TYPE_DENTRY: &str = "dentry";


const TYPE_UINT32: &str = "uint32";


const PATH_INDEX: u32 = 0;


const MODE_INDEX: u32 = 1;


const DENTRY_INDEX: u32 = 1;


const RENAME_SOURCE_DIR_INDEX: u32 = 0;


const RENAME_SOURCE_INDEX: u32 = 1;


const RENAME_TARGET_DIR_INDEX: u32 = 2;


const RENAME_TARGET_INDEX: u32 = 3;


const LINK_EXISTING_INDEX: u32 = 0;


const LINK_DIR_INDEX: u32 = 1;


const LINK_CREATED_INDEX: u32 = 2;


const POSTFIX_VALUES: usize = 4;


const MMAP_PROT_INDEX: u32 = 1;


const MMAP_FLAGS_INDEX: u32 = 2;


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


/// The policies of a role: a group of paths over a cap, or a kprobe over the selectors one Tetragon kprobe takes, is refused, never split or cut.
pub fn build_policies(role: &Role, limits: &Limits) -> Result<Vec<TracingPolicy>, PolicyError> {
    let sets = watch_sets(role);
    let max = limits.max_selector_values;
    check_groups(&sets, max)?;
    let groups = [
        (policy_name(&role.name), content_kprobes(&sets, max)),
        (names_policy_name(&role.name), name_kprobes(&sets, max)),
        (ancestor_policy_name(&role.name), ancestor_kprobes(&sets, max)),
        (delete_policy_name(&role.name), delete_kprobes(&sets, max)),
        (attribute_policy_name(&role.name), attribute_kprobes(&sets, max)),
        (token_policy_name(&role.name), in_namespace(token_kprobes(&sets, max), HOST_BOTH)),
        (reversed_names_policy_name(&role.name), reversed_name_kprobes(&sets, max)),
        (reversed_ancestor_policy_name(&role.name), reversed_ancestor_kprobes(&sets, max)),
        (
            reversed_token_policy_name(&role.name),
            in_namespace(reversed_token_kprobes(&sets, max), HOST_BOTH),
        ),
        (
            full_source_policy_name(&role.name),
            in_namespace(full_source_kprobes(&sets, max), HOST_BOTH),
        ),
        (
            full_target_policy_name(&role.name),
            in_namespace(full_target_kprobes(&sets, max), HOST_BOTH),
        ),
        (full_name_policy_name(&role.name), in_namespace(full_name_kprobes(&sets, max), HOST_BOTH)),
        (
            foreign_open_policy_name(&role.name),
            in_namespace(vec![open_kprobe(&sets, max)], FOREIGN_MOUNT),
        ),
        (
            foreign_token_policy_name(&role.name),
            in_namespace(token_kprobes(&sets, max), FOREIGN_MOUNT),
        ),
        (
            foreign_reversed_token_policy_name(&role.name),
            in_namespace(reversed_token_kprobes(&sets, max), FOREIGN_MOUNT),
        ),
        (
            foreign_full_source_policy_name(&role.name),
            in_namespace(full_source_kprobes(&sets, max), FOREIGN_MOUNT),
        ),
        (
            foreign_full_target_policy_name(&role.name),
            in_namespace(full_target_kprobes(&sets, max), FOREIGN_MOUNT),
        ),
        (
            foreign_full_name_policy_name(&role.name),
            in_namespace(full_name_kprobes(&sets, max), FOREIGN_MOUNT),
        ),
        (
            user_open_policy_name(&role.name),
            in_namespace(vec![open_kprobe(&sets, max)], FOREIGN_USER),
        ),
        (user_token_policy_name(&role.name), in_namespace(token_kprobes(&sets, max), FOREIGN_USER)),
        (
            user_reversed_token_policy_name(&role.name),
            in_namespace(reversed_token_kprobes(&sets, max), FOREIGN_USER),
        ),
        (
            user_full_source_policy_name(&role.name),
            in_namespace(full_source_kprobes(&sets, max), FOREIGN_USER),
        ),
        (
            user_full_target_policy_name(&role.name),
            in_namespace(full_target_kprobes(&sets, max), FOREIGN_USER),
        ),
        (
            user_full_name_policy_name(&role.name),
            in_namespace(full_name_kprobes(&sets, max), FOREIGN_USER),
        ),
    ];
    let policies: Vec<TracingPolicy> = groups
        .into_iter()
        .map(|(name, kprobes)| tracing_policy(name, kprobes.into_iter().filter(|probe| !probe.selectors.is_empty()).collect()))
        .filter(|policy| !policy.spec.kprobes.is_empty())
        .collect();
    check_selector_counts(&policies, limits.max_kprobe_selectors)?;
    check_string_maps(&policies, limits)?;
    Ok(policies)
}


/// Refuses an empty role and a group of files, prefixes or honeytokens larger than one selector takes.
pub fn check_groups(sets: &WatchSets, max: usize) -> Result<(), PolicyError> {
    if sets.files.is_empty() && sets.prefixes.is_empty() && sets.tokens.is_empty() {
        Err(PolicyError::Empty)
    } else if sets.files.len() > max {
        Err(PolicyError::TooManyFiles {
            count: sets.files.len(),
            max,
        })
    } else if sets.prefixes.len() > max {
        Err(PolicyError::TooManyPrefixes {
            count: sets.prefixes.len(),
            max,
        })
    } else if sets.tokens.len() > max {
        Err(PolicyError::TooManyHoneytokens {
            count: sets.tokens.len(),
            max,
        })
    } else {
        Ok(())
    }
}


/// Refuses the first kprobe that needs more selectors than Tetragon takes.
pub fn check_selector_counts(policies: &[TracingPolicy], max: usize) -> Result<(), PolicyError> {
    let over = policies
        .iter()
        .flat_map(|policy| policy.spec.kprobes.iter())
        .find(|probe| probe.selectors.len() > max);
    over.map_or(Ok(()), |probe| {
        Err(PolicyError::TooManySelectors {
            call: probe.call.clone(),
            count: probe.selectors.len(),
            max,
        })
    })
}


/// Refuses the first policy with more `Equal` or `Prefix` selectors than one Tetragon policy loads (each takes a BPF map of its own).
pub fn check_string_maps(policies: &[TracingPolicy], limits: &Limits) -> Result<(), PolicyError> {
    [
        (OPERATOR_EQUAL, limits.max_equal_selectors),
        (OPERATOR_PREFIX, limits.max_prefix_selectors),
        (OPERATOR_POSTFIX, limits.max_postfix_selectors),
    ]
    .into_iter()
    .try_for_each(|(operator, max)| {
        policies.iter().try_for_each(|policy| {
            let count = string_selectors(policy, operator);
            if count > max {
                Err(PolicyError::TooManyMaps {
                    policy: policy.metadata.name.clone(),
                    operator: operator.to_string(),
                    count,
                    max,
                })
            } else {
                Ok(())
            }
        })
    })
}


/// The selectors of a policy that match a string with the operator.
pub fn string_selectors(policy: &TracingPolicy, operator: &str) -> usize {
    policy
        .spec
        .kprobes
        .iter()
        .flat_map(|probe| probe.selectors.iter())
        .filter(|selector| selector.match_args.iter().any(|arg| arg.operator == operator))
        .count()
}


/// The files, prefixes and honeytokens of a role, and the directories above them (a rename of one of those moves what is watched).
pub fn watch_sets(role: &Role) -> WatchSets {
    let files = paths_of(role, WatchKind::File);
    let prefixes = paths_of(role, WatchKind::Prefix);
    let tokens: Vec<String> = role.honeytokens.iter().map(|token| token.path.clone()).collect();
    let directories: Vec<String> = prefixes.iter().map(|prefix| directory_of(prefix)).collect();
    let ancestors = unique(
        files
            .iter()
            .flat_map(|file| ancestors_of(file))
            .chain(directories.iter().flat_map(|directory| directory_and_ancestors(directory))),
    );
    let token_ancestors = unique(tokens.iter().flat_map(|token| ancestors_of(token)));
    let token_owners = role
        .honeytokens
        .iter()
        .flat_map(|token| {
            ancestors_of(&token.path)
                .into_iter()
                .chain(std::iter::once(token.path.clone()))
                .map(|path| TokenOwner { path, uid: token.owner_uid })
        })
        .collect();
    WatchSets {
        files,
        prefixes,
        tokens,
        ancestors,
        token_ancestors,
        token_owners,
    }
}


/// The directories above a path, outermost first, without the root.
pub fn ancestors_of(path: &str) -> Vec<String> {
    let components: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    (1..components.len())
        .map(|count| format!("/{}", components.iter().take(count).copied().collect::<Vec<&str>>().join("/")))
        .collect()
}


/// A directory preceded by the directories above it.
pub fn directory_and_ancestors(directory: &str) -> Vec<String> {
    ancestors_of(directory)
        .into_iter()
        .chain(std::iter::once(directory.to_string()))
        .collect()
}


/// The values without repeats, in first-seen order.
pub fn unique(values: impl Iterator<Item = String>) -> Vec<String> {
    values.fold(Vec::new(), |mut kept, value| {
        if !kept.contains(&value) {
            kept.push(value);
        }
        kept
    })
}


/// The values of the first list followed by the second, without repeats.
pub fn union(first: &[String], second: &[String]) -> Vec<String> {
    unique(first.iter().chain(second.iter()).cloned())
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


/// The name of the policy of a role that watches names (renames, links); each prefix differs so no role name collides.
pub fn names_policy_name(role_name: &str) -> String {
    format!("{NAMES_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that watches the directories above watched paths.
pub fn ancestor_policy_name(role_name: &str) -> String {
    format!("{ANCESTOR_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that watches renames and removals of honeytokens.
pub fn token_policy_name(role_name: &str) -> String {
    format!("{TOKEN_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that watches deletions and permission changes.
pub fn delete_policy_name(role_name: &str) -> String {
    format!("{DELETE_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that watches extended attributes and ACLs.
pub fn attribute_policy_name(role_name: &str) -> String {
    format!("{ATTRIBUTE_POLICY_PREFIX}{role_name}")
}


/// The policy names of a role, the ones `classify` matches exactly.
pub fn policy_names(role_name: &str) -> Vec<String> {
    vec![
        policy_name(role_name),
        names_policy_name(role_name),
        ancestor_policy_name(role_name),
        delete_policy_name(role_name),
        attribute_policy_name(role_name),
        token_policy_name(role_name),
        reversed_names_policy_name(role_name),
        reversed_ancestor_policy_name(role_name),
        reversed_token_policy_name(role_name),
        full_source_policy_name(role_name),
        full_target_policy_name(role_name),
        full_name_policy_name(role_name),
        foreign_open_policy_name(role_name),
        foreign_token_policy_name(role_name),
        foreign_reversed_token_policy_name(role_name),
        foreign_full_source_policy_name(role_name),
        foreign_full_target_policy_name(role_name),
        foreign_full_name_policy_name(role_name),
        user_open_policy_name(role_name),
        user_token_policy_name(role_name),
        user_reversed_token_policy_name(role_name),
        user_full_source_policy_name(role_name),
        user_full_target_policy_name(role_name),
        user_full_name_policy_name(role_name),
    ]
}


/// The name of the policy of a role that matches renames and links on the target and the new name, listed first (see the crate notes).
pub fn reversed_names_policy_name(role_name: &str) -> String {
    format!("{REVERSED_NAMES_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches renames of the directories above watched paths on the target, listed first.
pub fn reversed_ancestor_policy_name(role_name: &str) -> String {
    format!("{REVERSED_ANCESTOR_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches renames and links of honeytokens on the target and the new name, listed first.
pub fn reversed_token_policy_name(role_name: &str) -> String {
    format!("{REVERSED_TOKEN_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches the full dentry path of a rename source and of an unlink (a bind mount of the root filesystem).
pub fn full_source_policy_name(role_name: &str) -> String {
    format!("{FULL_SOURCE_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches the full dentry path of a rename target and of a directory removal.
pub fn full_target_policy_name(role_name: &str) -> String {
    format!("{FULL_TARGET_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches the full dentry path of a new symlink and of a new hard link name.
pub fn full_name_policy_name(role_name: &str) -> String {
    format!("{FULL_NAME_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches honeytoken opens outside the host mount namespace (never honeytoken severity).
pub fn foreign_open_policy_name(role_name: &str) -> String {
    format!("{FOREIGN_OPEN_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches honeytoken renames, removals and links outside the host mount namespace (never honeytoken severity).
pub fn foreign_token_policy_name(role_name: &str) -> String {
    format!("{FOREIGN_TOKEN_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches target-first honeytoken renames and links outside the host mount namespace (never honeytoken severity).
pub fn foreign_reversed_token_policy_name(role_name: &str) -> String {
    format!("{FOREIGN_REVERSED_TOKEN_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches the full-path rename source and unlink outside the host mount namespace (never honeytoken severity).
pub fn foreign_full_source_policy_name(role_name: &str) -> String {
    format!("{FOREIGN_FULL_SOURCE_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches the full-path rename target and rmdir outside the host mount namespace (never honeytoken severity).
pub fn foreign_full_target_policy_name(role_name: &str) -> String {
    format!("{FOREIGN_FULL_TARGET_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches the full-path new symlink and link name outside the host mount namespace (never honeytoken severity).
pub fn foreign_full_name_policy_name(role_name: &str) -> String {
    format!("{FOREIGN_FULL_NAME_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches honeytoken opens in the host mount namespace but another user namespace (never honeytoken severity).
pub fn user_open_policy_name(role_name: &str) -> String {
    format!("{USER_OPEN_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches honeytoken renames, removals and links in the host mount namespace but another user namespace (never honeytoken severity).
pub fn user_token_policy_name(role_name: &str) -> String {
    format!("{USER_TOKEN_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches target-first honeytoken renames and links in the host mount namespace but another user namespace (never honeytoken severity).
pub fn user_reversed_token_policy_name(role_name: &str) -> String {
    format!("{USER_REVERSED_TOKEN_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches the full-path rename source and unlink in the host mount namespace but another user namespace (never honeytoken severity).
pub fn user_full_source_policy_name(role_name: &str) -> String {
    format!("{USER_FULL_SOURCE_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches the full-path rename target and rmdir in the host mount namespace but another user namespace (never honeytoken severity).
pub fn user_full_target_policy_name(role_name: &str) -> String {
    format!("{USER_FULL_TARGET_POLICY_PREFIX}{role_name}")
}


/// The name of the policy of a role that matches the full-path new symlink and link name in the host mount namespace but another user namespace (never honeytoken severity).
pub fn user_full_name_policy_name(role_name: &str) -> String {
    format!("{USER_FULL_NAME_POLICY_PREFIX}{role_name}")
}


/// The kprobes on contents: writes, truncations, creations, shared mappings, opens of honeytokens (the split is explained in the crate notes).
pub fn content_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    let directories: Vec<String> = sets.prefixes.iter().map(|prefix| directory_of(prefix)).collect();
    let write_mask = mask_arg(MODE_INDEX, MAY_WRITE_MASK);
    let shared_mask = mask_arg(MMAP_FLAGS_INDEX, MAP_SHARED_MASK);
    vec![
        kprobe(
            HOOK_PERMISSION,
            &[(0, TYPE_FILE), (1, TYPE_INT)],
            false,
            watch_selectors(PATH_INDEX, &sets.files, &sets.prefixes, &[write_mask], max),
        ),
        kprobe(
            HOOK_PATH_TRUNCATE,
            &[(0, TYPE_PATH)],
            true,
            watch_selectors(PATH_INDEX, &sets.files, &sets.prefixes, &[], max),
        ),
        kprobe(
            HOOK_FILE_TRUNCATE,
            &[(0, TYPE_FILE)],
            true,
            watch_selectors(PATH_INDEX, &sets.files, &sets.prefixes, &[], max),
        ),
        kprobe(
            HOOK_MKNOD,
            &[(0, TYPE_PATH)],
            false,
            watch_selectors(PATH_INDEX, &[], &directories, &[], max),
        ),
        kprobe(
            HOOK_MMAP,
            &[(0, TYPE_FILE), (MMAP_PROT_INDEX, TYPE_UINT32), (MMAP_FLAGS_INDEX, TYPE_UINT32)],
            false,
            watch_selectors(PATH_INDEX, &sets.files, &sets.prefixes, &[shared_mask], max),
        ),
        bind_kprobe(open_kprobe(sets, max), HOST_BOTH),
    ]
}


/// The kprobe on opens of honeytokens, the resolved path of a `file` argument.
pub fn open_kprobe(sets: &WatchSets, max: usize) -> Kprobe {
    kprobe(
        HOOK_OPEN,
        &[(0, TYPE_FILE)],
        false,
        watch_selectors(PATH_INDEX, &sets.tokens, &[], &[], max),
    )
}


/// The kprobes with every selector bound to the (namespace, operator) conditions, ANDed: a path rendered in another namespace is not trusted.
pub fn in_namespace(kprobes: Vec<Kprobe>, conditions: &[(&str, &str)]) -> Vec<Kprobe> {
    kprobes.into_iter().map(|probe| bind_kprobe(probe, conditions)).collect()
}


/// One kprobe with the namespace conditions added to each of its selectors.
pub fn bind_kprobe(probe: Kprobe, conditions: &[(&str, &str)]) -> Kprobe {
    let selectors = probe
        .selectors
        .into_iter()
        .map(|selector| Selector {
            match_namespaces: conditions
                .iter()
                .map(|(namespace, operator)| MatchNamespace {
                    namespace: (*namespace).to_string(),
                    operator: (*operator).to_string(),
                    values: vec![HOST_NAMESPACE.to_string()],
                })
                .collect(),
            ..selector
        })
        .collect();
    Kprobe { selectors, ..probe }
}


/// The kprobes on names: a rename with the watched file or prefix as source or target, symlinks (also at a directory above) and hard links.
pub fn name_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    vec![
        rename_kprobe(&sets.files, &sets.prefixes, max),
        directory_kprobe(
            HOOK_SYMLINK,
            &union(&union(&sets.files, &sets.ancestors), &sets.token_ancestors),
            &sets.prefixes,
            max,
        ),
        link_kprobe(&sets.files, &sets.prefixes, max),
    ]
}


/// The kprobes on the directories above what is watched: a rename of one, and a removal of one or of a directory inside a prefix.
pub fn ancestor_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    vec![
        rename_kprobe(&sets.ancestors, &[], max),
        directory_kprobe(HOOK_RMDIR, &sets.ancestors, &sets.prefixes, max),
    ]
}


/// The kprobes on honeytokens: a rename, removal or hard link of one, or a rename or removal of a directory above it (opens are in the contents policy).
pub fn token_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    vec![
        rename_kprobe(&union(&sets.tokens, &sets.token_ancestors), &[], max),
        directory_kprobe(HOOK_UNLINK, &sets.tokens, &[], max),
        directory_kprobe(HOOK_RMDIR, &sets.token_ancestors, &[], max),
        link_kprobe(&sets.tokens, &[], max),
    ]
}


/// The reversed names kprobes: the target of a rename and the new name of a link, rendered first.
pub fn reversed_name_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    vec![
        reversed_rename_kprobe(&sets.files, &sets.prefixes, max),
        reversed_link_kprobe(&sets.files, &sets.prefixes, max),
    ]
}


/// The reversed kprobe on the directories above what is watched.
pub fn reversed_ancestor_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    vec![reversed_rename_kprobe(&sets.ancestors, &[], max)]
}


/// The reversed kprobes on honeytokens and the directories above them.
pub fn reversed_token_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    vec![
        reversed_rename_kprobe(&union(&sets.tokens, &sets.token_ancestors), &[], max),
        reversed_link_kprobe(&sets.tokens, &[], max),
    ]
}


/// Every path a name hook can name, the directories above included: the values of the full-path dentry selectors.
pub fn full_path_values(sets: &WatchSets) -> Vec<String> {
    union(&union(&sets.files, &sets.ancestors), &union(&sets.tokens, &sets.token_ancestors))
}


/// A kprobe listing the dentry first and matching its full path (`Equal` on paths, `Prefix` on prefixes): right on the root filesystem and through a bind mount of it.
pub fn full_path_kprobe(call: &str, first: u32, arguments: &[(u32, &str)], sets: &WatchSets, max: usize) -> Kprobe {
    kprobe(
        call,
        arguments,
        false,
        watch_selectors(first, &full_path_values(sets), &sets.prefixes, &[], max),
    )
}


/// The full-path kprobes on a rename source and an unlink.
pub fn full_source_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    vec![
        full_path_kprobe(
            HOOK_RENAME,
            RENAME_SOURCE_INDEX,
            &[
                (RENAME_SOURCE_INDEX, TYPE_DENTRY),
                (RENAME_SOURCE_DIR_INDEX, TYPE_PATH),
                (RENAME_TARGET_INDEX, TYPE_DENTRY),
                (RENAME_TARGET_DIR_INDEX, TYPE_PATH),
            ],
            sets,
            max,
        ),
        full_path_kprobe(
            HOOK_UNLINK,
            DENTRY_INDEX,
            &[(DENTRY_INDEX, TYPE_DENTRY), (PATH_INDEX, TYPE_PATH)],
            sets,
            max,
        ),
    ]
}


/// The full-path kprobes on a rename target and a directory removal.
pub fn full_target_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    vec![
        full_path_kprobe(
            HOOK_RENAME,
            RENAME_TARGET_INDEX,
            &[
                (RENAME_TARGET_INDEX, TYPE_DENTRY),
                (RENAME_TARGET_DIR_INDEX, TYPE_PATH),
                (RENAME_SOURCE_INDEX, TYPE_DENTRY),
                (RENAME_SOURCE_DIR_INDEX, TYPE_PATH),
            ],
            sets,
            max,
        ),
        full_path_kprobe(
            HOOK_RMDIR,
            DENTRY_INDEX,
            &[(DENTRY_INDEX, TYPE_DENTRY), (PATH_INDEX, TYPE_PATH)],
            sets,
            max,
        ),
    ]
}


/// The full-path kprobes on a new symlink and a new hard link name.
pub fn full_name_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    vec![
        full_path_kprobe(
            HOOK_SYMLINK,
            DENTRY_INDEX,
            &[(DENTRY_INDEX, TYPE_DENTRY), (PATH_INDEX, TYPE_PATH)],
            sets,
            max,
        ),
        full_path_kprobe(
            HOOK_LINK,
            LINK_CREATED_INDEX,
            &[
                (LINK_CREATED_INDEX, TYPE_DENTRY),
                (LINK_DIR_INDEX, TYPE_PATH),
                (LINK_EXISTING_INDEX, TYPE_DENTRY),
            ],
            sets,
            max,
        ),
    ]
}


/// A hard link kprobe matching the paths as the existing name (a dentry alone, so by name), listed first.
pub fn link_kprobe(files: &[String], prefixes: &[String], max: usize) -> Kprobe {
    kprobe(
        HOOK_LINK,
        &[
            (LINK_EXISTING_INDEX, TYPE_DENTRY),
            (LINK_DIR_INDEX, TYPE_PATH),
            (LINK_CREATED_INDEX, TYPE_DENTRY),
        ],
        false,
        name_selectors(LINK_EXISTING_INDEX, files, prefixes, max),
    )
}


/// A hard link kprobe matching the paths as the new name (directory path and dentry), listed first.
pub fn reversed_link_kprobe(files: &[String], prefixes: &[String], max: usize) -> Kprobe {
    kprobe(
        HOOK_LINK,
        &[
            (LINK_DIR_INDEX, TYPE_PATH),
            (LINK_CREATED_INDEX, TYPE_DENTRY),
            (LINK_EXISTING_INDEX, TYPE_DENTRY),
        ],
        false,
        split_selectors(LINK_DIR_INDEX, LINK_CREATED_INDEX, files, prefixes, max),
    )
}


/// A rename kprobe matching the paths as the source (directory path and dentry), listed first.
pub fn rename_kprobe(files: &[String], prefixes: &[String], max: usize) -> Kprobe {
    kprobe(
        HOOK_RENAME,
        &[
            (RENAME_SOURCE_DIR_INDEX, TYPE_PATH),
            (RENAME_SOURCE_INDEX, TYPE_DENTRY),
            (RENAME_TARGET_DIR_INDEX, TYPE_PATH),
            (RENAME_TARGET_INDEX, TYPE_DENTRY),
        ],
        false,
        split_selectors(RENAME_SOURCE_DIR_INDEX, RENAME_SOURCE_INDEX, files, prefixes, max),
    )
}


/// A rename kprobe matching the paths as the target (directory path and dentry), listed first.
pub fn reversed_rename_kprobe(files: &[String], prefixes: &[String], max: usize) -> Kprobe {
    kprobe(
        HOOK_RENAME,
        &[
            (RENAME_TARGET_DIR_INDEX, TYPE_PATH),
            (RENAME_TARGET_INDEX, TYPE_DENTRY),
            (RENAME_SOURCE_DIR_INDEX, TYPE_PATH),
            (RENAME_SOURCE_INDEX, TYPE_DENTRY),
        ],
        false,
        split_selectors(RENAME_TARGET_DIR_INDEX, RENAME_TARGET_INDEX, files, prefixes, max),
    )
}


/// A hook that gives the directory as a path (index 0) and the name as a dentry (index 1): unlink, rmdir, symlink.
pub fn directory_kprobe(call: &str, files: &[String], prefixes: &[String], max: usize) -> Kprobe {
    kprobe(
        call,
        &[(PATH_INDEX, TYPE_PATH), (DENTRY_INDEX, TYPE_DENTRY)],
        false,
        split_selectors(PATH_INDEX, DENTRY_INDEX, files, prefixes, max),
    )
}


/// The kprobes on deletions of files and on permission changes.
pub fn delete_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    vec![
        directory_kprobe(HOOK_UNLINK, &sets.files, &sets.prefixes, max),
        kprobe(
            HOOK_CHMOD,
            &[(0, TYPE_PATH)],
            false,
            watch_selectors(PATH_INDEX, &sets.files, &sets.prefixes, &[], max),
        ),
        kprobe(
            HOOK_CHOWN,
            &[(0, TYPE_PATH)],
            false,
            watch_selectors(PATH_INDEX, &sets.files, &sets.prefixes, &[], max),
        ),
    ]
}


/// The kprobes on extended attributes and ACLs, by the dentry (index 1 on kernels from 6.3, after the idmap).
pub fn attribute_kprobes(sets: &WatchSets, max: usize) -> Vec<Kprobe> {
    [
        (HOOK_SETXATTR, false),
        (HOOK_REMOVEXATTR, false),
        (HOOK_SET_ACL, true),
        (HOOK_REMOVE_ACL, true),
    ]
    .into_iter()
    .map(|(call, call_not_found)| {
        kprobe(
            call,
            &[(DENTRY_INDEX, TYPE_DENTRY)],
            call_not_found,
            name_selectors(DENTRY_INDEX, &sets.files, &sets.prefixes, max),
        )
    })
    .collect()
}


/// A prefix without its trailing slash: `security_path_mknod` reports the directory a file is created in.
pub fn directory_of(prefix: &str) -> String {
    prefix.strip_suffix('/').unwrap_or(prefix).to_string()
}


/// The directory of an absolute path (`/` for a top-level name).
pub fn parent_of(path: &str) -> String {
    let parent = path.rsplit_once('/').map_or("", |(parent, _)| parent);
    if parent.is_empty() { "/" } else { parent }.to_string()
}


/// The final component of a path with the slash before it, the form a `Postfix` match takes.
pub fn slash_name_of(path: &str) -> String {
    let name = path.rsplit('/').next().unwrap_or(path);
    format!("/{name}")
}


/// Selectors for a hook with a directory `path` and a name `dentry`: directories `Equal` times names `Postfix`, prefixes `Prefix` on the directory.
pub fn split_selectors(dir_index: u32, name_index: u32, files: &[String], prefixes: &[String], max_values: usize) -> Vec<Selector> {
    let size = max_values.max(1);
    let directories = unique(files.iter().map(|file| parent_of(file)));
    let names = unique(files.iter().map(|file| slash_name_of(file)));
    let exact = directories.chunks(size).flat_map(|dirs| {
        names.chunks(POSTFIX_VALUES.min(size)).map(move |chunk| Selector {
            match_args: vec![
                MatchArg {
                    index: dir_index,
                    operator: OPERATOR_EQUAL.to_string(),
                    values: dirs.to_vec(),
                },
                MatchArg {
                    index: name_index,
                    operator: OPERATOR_POSTFIX.to_string(),
                    values: chunk.to_vec(),
                },
            ],
            match_namespaces: Vec::new(),
        })
    });
    let tree_directories: Vec<String> = prefixes.iter().map(|prefix| directory_of(prefix)).collect();
    exact.chain(watch_selectors(dir_index, &[], &tree_directories, &[], max_values)).collect()
}


/// Selectors for a hook with a dentry alone: names `Postfix` (any file of that name), prefixes `Prefix` (right on the root filesystem only).
pub fn name_selectors(index: u32, files: &[String], prefixes: &[String], max_values: usize) -> Vec<Selector> {
    let size = max_values.max(1);
    let names = unique(files.iter().map(|file| slash_name_of(file)));
    let postfix = names.chunks(POSTFIX_VALUES.min(size)).map(|chunk| Selector {
        match_args: vec![MatchArg {
            index,
            operator: OPERATOR_POSTFIX.to_string(),
            values: chunk.to_vec(),
        }],
        match_namespaces: Vec::new(),
    });
    postfix.chain(watch_selectors(index, &[], prefixes, &[], max_values)).collect()
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


/// The selectors for exact paths (as many as the value cap needs) and for prefixes, each carrying the extra matches.
pub fn watch_selectors(index: u32, files: &[String], prefixes: &[String], extra: &[MatchArg], max_values: usize) -> Vec<Selector> {
    let size = max_values.max(1);
    let equal = files.chunks(size).map(|values| (OPERATOR_EQUAL, values));
    let prefix = prefixes.chunks(size).map(|values| (OPERATOR_PREFIX, values));
    equal
        .chain(prefix)
        .map(|(operator, values)| {
            let path = MatchArg {
                index,
                operator: operator.to_string(),
                values: values.to_vec(),
            };
            Selector {
                match_args: std::iter::once(path).chain(extra.iter().cloned()).collect(),
                match_namespaces: Vec::new(),
            }
        })
        .collect()
}
