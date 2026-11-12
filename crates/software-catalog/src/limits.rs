//! Default caps and the injectable limits.

pub const MAX_CATALOGUE_BYTES: usize = 1_048_576;


pub const MAX_ENTRIES: usize = 2048;


pub const MAX_INSTALLED: usize = 50_000;


pub const MAX_INSTALLED_BYTES: usize = 16_777_216;


pub const MAX_LINE_BYTES: usize = 512;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_catalogue_bytes: usize,
    pub max_entries: usize,
    pub max_installed: usize,
    pub max_installed_bytes: usize,
    pub max_line_bytes: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_catalogue_bytes: MAX_CATALOGUE_BYTES,
            max_entries: MAX_ENTRIES,
            max_installed: MAX_INSTALLED,
            max_installed_bytes: MAX_INSTALLED_BYTES,
            max_line_bytes: MAX_LINE_BYTES,
        }
    }
}
