pub const DEFAULT_MAX_BYTES: u64 = 16_777_216;


pub const DEFAULT_MAX_ITEMS: usize = 2_000;


pub const COLLECTION_SLACK: usize = 8;


pub const DEFAULT_MAX_CONTAINERS: usize = 64;


pub const DEFAULT_MAX_LABELS: usize = 128;


pub const DEFAULT_MAX_ADDRESSES: usize = 16;


pub const DEFAULT_MAX_TEXT_BYTES: usize = 512;


pub const PAGE_POD_BYTES: u64 = 32_768;


pub const MAX_CONTINUE_BYTES: usize = 4_096;


pub const DEFAULT_MAX_PAGES: usize = 64;


pub const DEFAULT_MAX_TOTAL_ITEMS: usize = 20_000;


pub const CEILING_PAGES: usize = 1_024;


pub const CEILING_TOTAL_ITEMS: usize = 200_000;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageLimits {
    pub max_pages: usize,
    pub max_total_items: usize,
}


impl Default for PageLimits {
    fn default() -> Self {
        Self {
            max_pages: DEFAULT_MAX_PAGES,
            max_total_items: DEFAULT_MAX_TOTAL_ITEMS,
        }
    }
}


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
