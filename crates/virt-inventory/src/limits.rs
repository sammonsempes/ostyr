pub const DEFAULT_MAX_BYTES: u64 = 16_777_216;


pub const DEFAULT_MAX_ITEMS: usize = 10_000;


pub const DEFAULT_MAX_TEXT_BYTES: usize = 512;


pub const DEFAULT_MAX_PATHS: usize = 10_000;


pub const DEFAULT_MAX_PRIVILEGES: usize = 128;


pub const DEFAULT_MAX_GRANTS: usize = 100_000;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_items: usize,
    pub max_text_bytes: usize,
    pub max_paths: usize,
    pub max_privileges: usize,
    pub max_grants: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_items: DEFAULT_MAX_ITEMS,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
            max_paths: DEFAULT_MAX_PATHS,
            max_privileges: DEFAULT_MAX_PRIVILEGES,
            max_grants: DEFAULT_MAX_GRANTS,
        }
    }
}
