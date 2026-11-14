pub const DEFAULT_MAX_BYTES: u64 = 67_108_864;


pub const CEILING_MAX_BYTES: u64 = 1_073_741_824;


pub const DEFAULT_MAX_FINDINGS: usize = 100_000;


pub const DEFAULT_MAX_RESOURCES: usize = 16;


pub const DEFAULT_MAX_LABELS: usize = 64;


pub const DEFAULT_MAX_UNMAPPED: usize = 64;


pub const DEFAULT_MAX_LIST: usize = 64;


pub const DEFAULT_MAX_FRAMEWORKS: usize = 256;


pub const DEFAULT_MAX_REQUIREMENTS: usize = 256;


pub const DEFAULT_MAX_TEXT_BYTES: usize = 1_024;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_findings: usize,
    pub max_resources: usize,
    pub max_labels: usize,
    pub max_unmapped: usize,
    pub max_list: usize,
    pub max_frameworks: usize,
    pub max_requirements: usize,
    pub max_text_bytes: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_findings: DEFAULT_MAX_FINDINGS,
            max_resources: DEFAULT_MAX_RESOURCES,
            max_labels: DEFAULT_MAX_LABELS,
            max_unmapped: DEFAULT_MAX_UNMAPPED,
            max_list: DEFAULT_MAX_LIST,
            max_frameworks: DEFAULT_MAX_FRAMEWORKS,
            max_requirements: DEFAULT_MAX_REQUIREMENTS,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
        }
    }
}
