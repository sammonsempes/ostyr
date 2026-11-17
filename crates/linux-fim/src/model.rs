use serde::{Deserialize, Serialize};


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_table_bytes: usize,
    pub max_roles: usize,
    pub max_watched: usize,
    pub max_honeytokens: usize,
    pub max_path_bytes: usize,
    pub max_selector_values: usize,
    pub max_kprobe_selectors: usize,
    pub max_equal_selectors: usize,
    pub max_prefix_selectors: usize,
    pub max_postfix_selectors: usize,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleTable {
    pub version: u32,
    pub roles: Vec<Role>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Role {
    pub name: String,
    #[serde(default)]
    pub watched: Vec<WatchedPath>,
    #[serde(default)]
    pub honeytokens: Vec<Honeytoken>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WatchedPath {
    pub path: String,
    pub kind: WatchKind,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WatchKind {
    File,
    Prefix,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Honeytoken {
    pub path: String,
    pub kind: HoneytokenKind,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoneytokenKind {
    Canary,
    AwsCredentials,
    SshKey,
    PasswordFile,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchSets {
    pub files: Vec<String>,
    pub prefixes: Vec<String>,
    pub tokens: Vec<String>,
    pub ancestors: Vec<String>,
    pub token_ancestors: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TracingPolicy {
    pub api_version: String,
    pub kind: String,
    pub metadata: Metadata,
    pub spec: Spec,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Metadata {
    pub name: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Spec {
    pub kprobes: Vec<Kprobe>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Kprobe {
    pub call: String,
    pub syscall: bool,
    pub args: Vec<KprobeArg>,
    pub ignore: Ignore,
    pub selectors: Vec<Selector>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KprobeArg {
    pub index: u32,
    #[serde(rename = "type")]
    pub arg_type: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Ignore {
    pub call_not_found: bool,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Selector {
    pub match_args: Vec<MatchArg>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub match_namespaces: Vec<MatchNamespace>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatchNamespace {
    pub namespace: String,
    pub operator: String,
    pub values: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MatchArg {
    pub index: u32,
    pub operator: String,
    pub values: Vec<String>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FimEvent {
    Write {
        path: String,
        process: String,
        name_match: bool,
        mount_ambiguous: bool,
        foreign_mount_ns: bool,
        dentry_path: Option<String>,
    },
    Honeytoken {
        path: String,
        process: String,
    },
    Link {
        existing: String,
        created: String,
        process: String,
        honeytoken: bool,
        name_match: bool,
        mount_ambiguous: bool,
        foreign_mount_ns: bool,
        created_dentry: Option<String>,
    },
    Rename {
        source: String,
        target: String,
        process: String,
        honeytoken: bool,
        mount_ambiguous: bool,
        foreign_mount_ns: bool,
        source_dentry: Option<String>,
        target_dentry: Option<String>,
    },
    MissingPath {
        policy: String,
        function: String,
        process: String,
    },
    Oversized {
        policy: String,
        bytes: usize,
    },
}
