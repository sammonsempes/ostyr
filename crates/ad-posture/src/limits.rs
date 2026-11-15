pub const DEFAULT_MAX_BYTES: u64 = 33_554_432;


pub const DEFAULT_MAX_ENTRIES: usize = 100_000;


pub const DEFAULT_MAX_VALUES: usize = 1_000;


pub const DEFAULT_MAX_TEXT_BYTES: usize = 1_024;


/// Bounds of one snapshot: bytes read, entries, values of one multi-valued attribute, bytes of one text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_entries: usize,
    pub max_values: usize,
    pub max_text_bytes: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_entries: DEFAULT_MAX_ENTRIES,
            max_values: DEFAULT_MAX_VALUES,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
        }
    }
}
