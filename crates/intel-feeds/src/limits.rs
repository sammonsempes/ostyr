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
