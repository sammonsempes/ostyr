use serde::Deserialize;
use std::collections::BTreeMap;


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
