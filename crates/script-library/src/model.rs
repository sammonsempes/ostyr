use crate::types::Params;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;


pub const MAX_NAME_LENGTH: usize = 64;


pub const MAX_PARAMETERS: usize = 32;


pub const MAX_ENUM_VALUES: usize = 64;


pub const MAX_PREFIXES: usize = 16;


pub const MAX_STRING_LENGTH: usize = 4096;


pub const MAX_PATH_LENGTH: usize = 1024;


pub const MAX_PATTERN_LENGTH: usize = 256;


pub const PATTERN_SIZE_LIMIT: usize = 65_536;


pub const MAX_TIMEOUT_SECONDS: u64 = 86_400;


pub const MAX_OUTPUT_BYTES: u64 = 16_777_216;


pub const MAX_MANIFEST_BYTES: usize = 65_536;


pub const MAX_SECRET_PATTERNS: usize = 16;


pub const MIN_MEMORY_BYTES: u64 = 1_048_576;


pub const MAX_MEMORY_BYTES: u64 = 17_179_869_184;


pub const DEFAULT_MEMORY_BYTES: u64 = 536_870_912;


pub const MAX_PIDS: u64 = 4096;


pub const DEFAULT_PIDS: u64 = 256;


pub const MAX_CPU_PERCENT: u64 = 6400;


pub const REDACTION_SLACK_BYTES: u64 = 65_536;


pub const READ_SLACK_COUNT: u64 = 2;


pub const REDACTION_MARK: &[u8] = b"[REDACTED]";


pub const SHA256_HEX_LENGTH: usize = 64;


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Interpreter {
    Powershell,
    Bash,
    Python,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(tag = "type", deny_unknown_fields)]
pub enum ParamKind {
    #[serde(rename = "string")]
    Text {
        #[serde(default)]
        min_length: usize,
        max_length: usize,
        pattern: Option<String>,
    },
    #[serde(rename = "integer")]
    Integer { min: i64, max: i64 },
    #[serde(rename = "enum")]
    Enumeration { values: Vec<String> },
    #[serde(rename = "path")]
    Path { allowed_prefixes: Vec<String> },
}


/// Per-run cgroup limits; a manifest that declares none gets the defaults, never an unlimited run. `cpu_percent` is of one CPU.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Limits {
    pub memory_bytes: u64,
    pub pids: u64,
    pub cpu_percent: Option<u64>,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            memory_bytes: DEFAULT_MEMORY_BYTES,
            pids: DEFAULT_PIDS,
            cpu_percent: None,
        }
    }
}


/// The limit a run ran into, read back from the cgroup: a memory kill, or a refused fork.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitHit {
    Memory,
    Pids,
}


/// The unprivileged user the script runs as, so it cannot write the delegated cgroup root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RunAs {
    pub uid: u32,
    pub gid: u32,
}


/// `script` is relative to the library root; `sha256` is lowercase hex.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub name: String,
    pub interpreter: Interpreter,
    pub script: String,
    pub sha256: String,
    pub timeout_seconds: u64,
    pub max_output_bytes: u64,
    #[serde(default)]
    pub parameters: BTreeMap<String, ParamKind>,
    #[serde(default)]
    pub secret_patterns: Vec<String>,
    #[serde(default)]
    pub limits: Limits,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParamValue {
    Text(String),
    Integer(i64),
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Argv {
    pub program: String,
    pub args: Vec<String>,
}


/// Everything one launch needs; `environment` is a snapshot of the caller's variables, of which only the allowlist is passed on.
#[derive(Debug, Clone)]
pub struct LaunchRequest {
    pub manifest: Manifest,
    pub params: Params,
    pub script_bytes: Vec<u8>,
    pub work_root: PathBuf,
    pub cgroup_root: PathBuf,
    pub kill_grace: Duration,
    pub environment: Vec<(String, String)>,
    pub run_as: Option<RunAs>,
}


/// `exit_code` is `None` when the process was killed; `dropped_bytes` counts the output beyond the cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub output: Vec<u8>,
    pub dropped_bytes: u64,
    pub limit_hit: Option<LimitHit>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub bytes: Vec<u8>,
    pub dropped: u64,
}
