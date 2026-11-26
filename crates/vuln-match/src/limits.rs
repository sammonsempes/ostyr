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


pub const MAX_RETAINED_ITEMS: u64 = 5_000_000;


/// Memory budget of one feed load while the previous record set is alive, the archive buffer included.
pub const MAX_FEED_MEMORY_BYTES: u64 = 2_147_483_648;


/// Worst bytes per retained item measured live on a hostile archive (T914C c2: 2 036 592 kB over 3 rounds for 5.94 M items of 40-byte names).
pub const FEED_BYTES_PER_ITEM: u64 = 176;


/// Record sets alive at the peak of a reload: the loaded one and the one being built.
pub const FEED_SETS_ALIVE: u64 = 2;


/// Ecosystems one feed setting may name.
pub const MAX_FEED_ECOSYSTEMS: usize = 16;


pub const MAX_ECOSYSTEM_CHARS: usize = 64;


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


pub const MAX_KEV_BYTES: u64 = 8_388_608;


pub const MAX_KEV_ENTRIES: usize = 100_000;


pub const MAX_EPSS_BYTES: u64 = 134_217_728;


pub const MAX_EPSS_ROWS: usize = 1_000_000;


pub const MAX_EPSS_LINE_BYTES: usize = 1024;


pub const MAX_CATALOGUE_TEXT_CHARS: usize = 128;


pub const CVE_ID_PREFIX: &str = "CVE";


pub const CVE_YEAR_DIGITS: usize = 4;


pub const CVE_SEQUENCE_MIN_DIGITS: usize = 4;


pub const CVE_SEQUENCE_MAX_DIGITS: usize = 7;


pub const CVE_ID_PARTS: usize = 3;


pub const CUT_MARKER: &str = "[cut]";


pub const EPSS_HEADER: &str = "cve,epss,percentile";


pub const EPSS_META_PREFIX: &str = "#";


pub const EPSS_MODEL_KEY: &str = "model_version";


pub const EPSS_DATE_KEY: &str = "score_date";


pub const MAX_OPEN_FINDINGS_PER_TENANT: u64 = 2_000_000;


pub const MAX_RESOLVED_FINDINGS_PER_TENANT: u64 = 1_000_000;


pub const MAX_RESOLVED_FINDINGS_PER_ASSET: u64 = 100_000;


pub const LAST_SEEN_GRANULARITY_MICROS: u64 = 3_600_000_000;


pub const MAX_FINDINGS_PER_SCAN: usize = 50_000;


pub const MAX_FIELD_BYTES: usize = 128;


pub const MAX_ALIASES_PER_FINDING: usize = 100;


pub const MAX_PAGE_LIMIT: usize = 500;


pub const MAX_PRIORITY_DIGITS: usize = 10;


pub const CURSOR_FIELDS: usize = 5;


pub const MAX_CURSOR_BYTES: usize = MAX_PRIORITY_DIGITS + (CURSOR_FIELDS - 1) * MAX_FIELD_BYTES + CURSOR_FIELDS - 1;


/// Open findings one asset's detail serves; one more is fetched to set `truncated`.
pub const MAX_ASSET_FINDINGS: usize = 1_000;


pub const DEFAULT_PAGE_LIMIT: usize = 50;
