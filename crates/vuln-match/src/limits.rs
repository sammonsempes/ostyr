//! Every cap of the crate.

pub const MAX_RECORD_BYTES: usize = 1_048_576;


pub const MAX_RECORDS: usize = 100_000;


pub const MAX_AFFECTED_PER_RECORD: usize = 4096;


pub const MAX_RANGES_PER_AFFECTED: usize = 64;


pub const MAX_EVENTS_PER_RANGE: usize = 1024;


pub const MAX_VERSIONS_PER_AFFECTED: usize = 65_536;


pub const MAX_VERSION_BYTES: usize = 256;


pub const MAX_EOL_ENTRIES: usize = 10_000;


pub const MAX_ARCHIVE_BYTES: u64 = 268_435_456;


pub const MAX_ARCHIVE_ENTRIES: usize = MAX_RECORDS;


pub const MAX_ENTRY_BYTES: u64 = MAX_RECORD_BYTES as u64;


pub const MAX_TOTAL_BYTES: u64 = 536_870_912;


pub const MAX_COMPRESSION_RATIO: u64 = 200;


pub const RATIO_FLOOR_BYTES: u64 = 65_536;


pub const MAX_LOGGED_NAME_CHARS: usize = 128;


pub const MAX_EOCD_SEARCH: usize = 65_557;


pub const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];


pub const EOCD_COUNT_OFFSET: usize = 10;


pub const ZIP64_LOCATOR_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x06, 0x07];


pub const ZIP64_LOCATOR_BYTES: usize = 20;


pub const ZIP64_LOCATOR_OFFSET: usize = 8;


pub const ZIP64_EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];


pub const ZIP64_COUNT_OFFSET: usize = 32;


pub const MAX_RETAINED_ITEMS: u64 = 2_000_000;


pub const CENTRAL_HEADER_MIN_BYTES: u64 = 46;


pub const EOCD_SIZE_OFFSET: usize = 12;


pub const EOCD_OFFSET_OFFSET: usize = 16;


pub const ZIP64_SIZE_OFFSET: usize = 40;


pub const PAIR: usize = 2;
