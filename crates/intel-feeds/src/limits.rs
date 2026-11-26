pub const MAX_LINE_BYTES: usize = 16_384;


pub const MAX_OBJECT_BYTES: usize = 65_536;


pub const MAX_DOCUMENT_BYTES: usize = 67_108_864;


pub const MAX_MISP_ATTRIBUTES: usize = 100_000;


pub const MAX_PATTERN_BYTES: usize = 4_096;


pub const MAX_COMPARISONS_PER_PATTERN: usize = 64;


pub const MAX_TAGS_PER_FIELD: usize = 16;


pub const MAX_TAG_BYTES: usize = 64;


pub const MAX_REPORTED_SKIPS: usize = 20;


pub const MAX_URL_BYTES: usize = 2_048;


pub const MAX_CONFIDENCE: u8 = 100;


pub const DEFAULT_CONFIDENCE: u8 = 50;


pub const MD5_HEX_LENGTH: usize = 32;


pub const SHA1_HEX_LENGTH: usize = 40;


pub const SHA256_HEX_LENGTH: usize = 64;


pub const DEFAULT_FEED_VERSION: &str = "unversioned";


pub const MAX_ROWS_PER_BATCH: usize = 10_000;


pub const MAX_BATCH_BYTES: usize = 1_048_576;


pub const MAX_IDENTIFIER_BYTES: usize = 64;


pub const DEFAULT_TTL_SECONDS: u32 = 2_592_000;


pub const DEFAULT_DICTIONARY_PORT: u16 = 9440;


pub const DEFAULT_DICTIONARY_USER: &str = "ostyr_dict";


pub const DEFAULT_TIMEOUT_MS: u64 = 30_000;


pub const MAX_TIMEOUT_MS: u64 = 600_000;


pub const MAX_USER_BYTES: usize = 64;


pub const MAX_READ_ROWS: usize = 250_000;


pub const MAX_READ_BYTES: u64 = 67_108_864;


pub const MAX_SAMPLE_CHARS: usize = 128;


pub const MIN_IPV4_PREFIX: u8 = 8;


pub const MIN_IPV6_PREFIX: u8 = 16;


pub const EMBEDDING_PREFIX: u8 = 96;


pub const EMBEDDING_SHIFT: u32 = 32;


pub const MAPPED_HEAD: u128 = 0xffff;


pub const EMBEDDING_HEADS: [u128; 3] = [MAPPED_HEAD, 0, 0x0064_ff9b_0000_0000_0000_0000];


pub const LOCAL_NAT64_SHIFT: u32 = 80;


pub const LOCAL_NAT64_MIN_PREFIX: u8 = 104;


pub const LOCAL_NAT64_HEAD: u128 = 0x0064_ff9b_0001;


pub const EMBEDDING_BASES: [u128; 4] = [
    MAPPED_HEAD << EMBEDDING_SHIFT,
    0,
    0x0064_ff9b_0000_0000_0000_0000_0000_0000,
    0x0064_ff9b_0001_0000_0000_0000_0000_0000,
];


pub const MAX_TAXII_OBJECTS_PER_PAGE: usize = 1_000;


pub const MAX_TAXII_NEXT_BYTES: usize = 1_024;


pub const MAX_TAXII_COLLECTION_BYTES: usize = 64;


pub const MAX_TAXII_HEADER_BYTES: usize = 64;


pub const DEFAULT_TAXII_MAX_PAGES: u32 = 10;


pub const LIMIT_TAXII_MAX_PAGES: u32 = 100;


pub const DEFAULT_TAXII_PAGE_LIMIT: u32 = 500;


pub const LIMIT_TAXII_PAGE_LIMIT: u32 = 1_000;


pub const MAX_TAXII_IOCS: usize = 250_000;


pub const CURSOR_SKEW_SECONDS: i64 = 300;


pub const TAXII_ACCEPT: &str = "application/taxii+json;version=2.1";


pub const TAXII_DATE_HEADER: &str = "X-TAXII-Date-Added-Last";


pub const MAX_RETRO_MATCHES: usize = 499;


pub const MAX_RETRO_SECONDS: u32 = 600;


pub const MAX_RETRO_ROWS_TO_READ: u64 = 4_000_000_000;


pub const MAX_RETRO_ROWS_TO_GROUP: u64 = 10_000_000;


pub const MAX_RETRO_BYTES: u64 = 4_194_304;


pub const MAX_RETRO_SCALAR_BYTES: u64 = 64;


pub const RETRO_HOST_CHARS: usize = 256;


pub const MIN_RETRO_INTERVAL_SECONDS: u64 = 60;


pub const MAX_RETRO_INTERVAL_SECONDS: u64 = 86_400;


pub const DEFAULT_RETRO_MARGIN_SECONDS: u64 = 300;


pub const MAX_RETRO_MARGIN_SECONDS: u64 = 3_600;


pub const MAX_RETRO_WINDOW_SECONDS: u64 = 604_800;


pub const NANOS_PER_MICRO: i128 = 1_000;


pub const MAX_PG_SETTINGS_BYTES: usize = 4_096;


pub const MAX_STATE_BYTES: u64 = 85;


pub const MAX_STATE_SKEW_SECONDS: i64 = 600;


pub const STATE_MODE: u32 = 0o600;


pub const STATE_RADIX: u32 = 10;


pub const MIN_INTERVAL_SECONDS: u64 = 60;


pub const MAX_INTERVAL_SECONDS: u64 = 86_400;


pub const MAX_ROUNDS: u64 = 10_000_000;


pub const MAX_LOGGED_FEED_NAMES: usize = 10;


pub const ROUND_CAP_EXIT_CODE: u8 = 3;


pub const MAX_FEED_FILE_BYTES: u64 = 268_435_456;
