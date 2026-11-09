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


pub const MAX_RETAINED_ITEMS: u64 = 2_000_000;


pub const MAGIC_BYTES: usize = 4;


pub const LOCAL_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x03, 0x04];


pub const CENTRAL_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x01, 0x02];


pub const EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x05, 0x06];


pub const ZIP64_EOCD_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x06, 0x06];


pub const DESCRIPTOR_SIGNATURE: [u8; 4] = [0x50, 0x4b, 0x07, 0x08];


pub const DESCRIPTOR_LENGTHS: [usize; 2] = [12, 20];


pub const LOCAL_FIXED_BYTES: usize = 26;


pub const LOCAL_FLAGS_AT: usize = 2;


pub const LOCAL_METHOD_AT: usize = 4;


pub const LOCAL_COMPRESSED_AT: usize = 14;


pub const LOCAL_NAME_AT: usize = 22;


pub const LOCAL_EXTRA_AT: usize = 24;


pub const ENCRYPTED_FLAG: u16 = 1;


pub const DESCRIPTOR_FLAG: u16 = 8;


pub const METHOD_STORED: u16 = 0;


pub const METHOD_DEFLATED: u16 = 8;
