pub const MAX_NAME_BYTES: usize = 253;


pub const WILDCARD_PREFIX: &str = "*.";


pub const DEFAULT_TTL_SECONDS: u32 = 300;


pub const DEFAULT_REFRESH_SECONDS: u32 = 3_600;


pub const DEFAULT_RETRY_SECONDS: u32 = 600;


pub const DEFAULT_EXPIRE_SECONDS: u32 = 86_400;


pub const DEFAULT_NEGATIVE_TTL_SECONDS: u32 = 300;


pub const DEFAULT_MIN_CONFIDENCE: u8 = 50;


pub const DEFAULT_MAX_RECORDS: usize = 100_000;


pub const MAX_RECORDS_LIMIT: usize = 10_000_000;


pub const SERIAL_DAY_UNIT: u32 = 100;


pub const SERIAL_MONTH_UNIT: u32 = 100;


pub const SERIAL_YEAR_UNIT: u32 = 10_000;


pub const MIN_ZERO_RUN: usize = 2;


pub const DEFAULT_UNBOUND_TIMEOUT_SECONDS: u64 = 10;


pub const MAX_UNBOUND_TIMEOUT_SECONDS: u64 = 300;


pub const MAX_SETTING_BYTES: usize = 4_096;


pub const DEFAULT_UNBOUND_COMMAND: &str = "unbound-control";


pub const DEFAULT_ZONEFILE: &str = "/var/lib/unbound/rpz.zone";


pub const RELOAD_SUBCOMMAND: &str = "auth_zone_reload";


pub const RELOAD_AUDIT_ACTION: &str = "dns-rpz.zone_reload";


pub const CLICKHOUSE_PREFIX: &str = "clickhouse:";


pub const SOURCE_FAILED: &str = "IOC read from ClickHouse failed";


pub const MAX_PAGE_TEXT_CHARS: usize = 120;


pub const MAX_PORT_DIGITS: usize = 5;


pub const MAX_HOST_HEADER_BYTES: usize = MAX_NAME_BYTES + 1 + MAX_PORT_DIGITS;


pub const ESCAPE_FACTOR: usize = 6;


pub const PAGE_FIXED_BYTES: usize = 2_048;


pub const HOST_SHOWN_COUNT: usize = 2;


pub const MAX_PAGE_BYTES: usize = PAGE_FIXED_BYTES + ESCAPE_FACTOR * (HOST_SHOWN_COUNT * MAX_NAME_BYTES + 2 * MAX_PAGE_TEXT_CHARS);


pub const UNKNOWN_DOMAIN_EN: &str = "unknown domain";


pub const UNKNOWN_DOMAIN_FR: &str = "domaine inconnu";


pub const DEFAULT_SINKHOLE_MAX_CONNECTIONS: usize = 512;


pub const MAX_SINKHOLE_CONNECTIONS: usize = 10_000;


pub const DEFAULT_SINKHOLE_PER_SOURCE: usize = 8;


pub const MAX_SINKHOLE_PER_SOURCE: usize = 256;


pub const DEFAULT_HEADER_READ_TIMEOUT_MS: u64 = 5_000;


pub const MAX_HEADER_READ_TIMEOUT_MS: u64 = 60_000;


pub const DEFAULT_RESPONSE_TIMEOUT_MS: u64 = 10_000;


pub const MAX_RESPONSE_TIMEOUT_MS: u64 = 300_000;


pub const MAX_REQUEST_HEAD_BYTES: usize = 8_192;


pub const MAX_REQUEST_HEADERS: usize = 32;


pub const ACCEPT_BACKOFF_MILLIS: u64 = 100;


pub const REPORT_INTERVAL_SECONDS: u64 = 60;


pub const IPV6_HOST_BITS: u32 = 64;


pub const HTML_TYPE: &str = "text/html; charset=utf-8";


pub const CSP_VALUE: &str = "default-src 'none'";


pub const ALLOWED_METHODS: &str = "GET, HEAD";


pub const REFUSED_TEXT: &str = "connections refused at the caps";


pub const CUT_TEXT: &str = "connections cut by a deadline or a protocol error";


pub const FAILED_TEXT: &str = "accepts that failed";


pub const COUNTER_CLASSES: usize = 3;


pub const MIN_INTERVAL_SECONDS: u64 = 60;


pub const MAX_INTERVAL_SECONDS: u64 = 86_400;


pub const MAX_ROUNDS: u64 = 1_000_000;


pub const MAX_SERVICE_SETTINGS_BYTES: u64 = 4_096;


pub const SERVICE_ALLOWED_PUNCTUATION: &[u8] = b" \n._:-/";


pub const SERVICE_FILE_CLASS: &str = "service file";


pub const SERVICE_SECTION: &str = "rpz-service";


pub const SERVICE_UNBOUND_COMMAND: &str = "/usr/sbin/unbound-control";


pub const ROUND_FAILED_AUDIT_ACTION: &str = "dns-rpz.round_failed";


pub const SERVICE_ACTOR: &str = "ostyr-dns-rpz";


pub const SERVICE_TENANT: &str = "system";


pub const SERVICE_MODULE: &str = "dns-rpz";


pub const STAGE_GENERATION: &str = "generation";


pub const STAGE_ZONE_FILE: &str = "zone_file";


pub const ROUND_CAP_EXIT_CODE: u8 = 3;


pub const DEBOUNCE_MILLIS: u64 = 300;


pub const AUDIT_DECLARED_KEYS: [&str; 7] = ["result", "diff", "reason", "changed_settings", "changed_files", "diff_sha256", "stage"];
