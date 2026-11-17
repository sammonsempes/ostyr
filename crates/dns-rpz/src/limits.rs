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
