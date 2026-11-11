use serde::{Deserialize, Serialize};


pub const DEFAULT_MAX_BYTES: usize = 16 << 20;


pub const DEFAULT_MAX_FINDINGS: usize = 10_000;


pub const DEFAULT_KEPT_CHARS: usize = 4;


pub const DEFAULT_EXCERPT_CHARS: usize = 200;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_findings: usize,
    pub kept_chars: usize,
    pub excerpt_chars: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_findings: DEFAULT_MAX_FINDINGS,
            kept_chars: DEFAULT_KEPT_CHARS,
            excerpt_chars: DEFAULT_EXCERPT_CHARS,
        }
    }
}


/// The scan scope file: glob patterns of paths whose findings are dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScanScope {
    #[serde(default)]
    pub skipped_paths: Vec<String>,
}


/// Location, rule and masked excerpt only; nothing derived from the secret beyond the masked prefix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    pub file: String,
    pub file_digest: String,
    pub start_line: u64,
    pub end_line: u64,
    pub commit: Option<String>,
    pub rule_id: String,
    pub excerpt: String,
}


/// One report belongs to one tenant and one scan scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Report {
    pub tenant: String,
    pub scope_id: String,
    pub findings: Vec<Finding>,
    pub malformed: usize,
    pub skipped: usize,
}
