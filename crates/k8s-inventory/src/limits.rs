pub const DEFAULT_MAX_BYTES: u64 = 33_554_432;


pub const DEFAULT_MAX_ITEMS: usize = 100_000;


pub const DEFAULT_MAX_CONTAINERS: usize = 64;


pub const DEFAULT_MAX_LABELS: usize = 128;


pub const DEFAULT_MAX_ADDRESSES: usize = 16;


pub const DEFAULT_MAX_TEXT_BYTES: usize = 512;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_items: usize,
    pub max_containers: usize,
    pub max_labels: usize,
    pub max_addresses: usize,
    pub max_text_bytes: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_items: DEFAULT_MAX_ITEMS,
            max_containers: DEFAULT_MAX_CONTAINERS,
            max_labels: DEFAULT_MAX_LABELS,
            max_addresses: DEFAULT_MAX_ADDRESSES,
            max_text_bytes: DEFAULT_MAX_TEXT_BYTES,
        }
    }
}
