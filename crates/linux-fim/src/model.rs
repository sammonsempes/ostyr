use crate::error::PlantRefusal;
use crate::types::{ExistsFn, Identity, IdentityFn, RunFn, Sha256Digest};
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
    #[serde(default)]
    pub owner_uid: u32,
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
    pub planted: Vec<PlantedIdentity>,
}


/// The identity of a planted file or of a directory above one: the kernel device number (`s_dev`) and the inode number, recorded at plant time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlantedIdentity {
    pub path: String,
    pub device: u32,
    pub inode: u64,
}


/// The identities planted by one run (directories above a token included, no path twice) and the tokens refused alone, by index.
#[derive(Debug)]
pub struct PlantReport {
    pub planted: Vec<PlantedIdentity>,
    pub refused: Vec<(usize, PlantRefusal)>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolve: Option<String>,
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
        /// The bare dentry of the link source: it can read like a declared path, so it never gives honeytoken severity.
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


/// What the package database says about the new content of a watched file; it annotates an event and never changes its severity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "result", rename_all = "snake_case")]
pub enum PackageVerdict {
    Match {
        package: String,
        evra: String,
        algo: &'static str,
        installed_at: u64,
    },
    Mismatch {
        package: String,
        evra: String,
    },
    Config,
    UnverifiableDigest {
        algo: &'static str,
    },
    Unowned,
    AmbiguousOwner,
    Unverified {
        reason: &'static str,
    },
    NotApplicable,
}


/// The content of a file as the caller read it from one `O_NOFOLLOW` handle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileEvidence {
    pub path: String,
    pub sha256: Sha256Digest,
    pub identity: Identity,
}


/// The exit code and the standard output of a package tool.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolOutput {
    pub code: i32,
    pub stdout: String,
}


/// The system calls package correlation makes; a test replaces them.
#[derive(Debug, Clone, Copy)]
pub struct PackageOps {
    pub run: RunFn,
    pub identity: IdentityFn,
    pub exists: ExistsFn,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Rpm,
    Dpkg,
}
