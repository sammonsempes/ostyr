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
}


/// A leaf cgroup created for one run, removed on drop.
#[derive(Debug)]
pub struct CgroupGuard {
    pub path: PathBuf,
}


/// `exit_code` is `None` when the process was killed; `dropped_bytes` counts the output beyond the cap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub output: Vec<u8>,
    pub dropped_bytes: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Captured {
    pub bytes: Vec<u8>,
    pub dropped: u64,
}
