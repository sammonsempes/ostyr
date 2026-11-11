pub const MAX_FILE_BYTES: u64 = 262_144;


pub const MAX_NAME_LEN: u64 = 64;


pub const MAX_LAYERS: u64 = 8;


pub const MAX_PARTICIPANTS: u64 = 32;


pub const MAX_OVERRIDES: u64 = 256;


pub const MAX_HOLIDAYS: u64 = 366;


pub const MAX_PERIOD_DAYS: u64 = 366;


pub const MAX_LEVELS: u64 = 10;


pub const MAX_TARGETS: u64 = 16;


pub const SECONDS_PER_DAY: u64 = 86_400;


pub const MAX_DELAY_DAYS: u64 = 7;


pub const MAX_DELAY_SECONDS: u64 = MAX_DELAY_DAYS * SECONDS_PER_DAY;


pub const MAX_SILENCES: u64 = 1024;


pub const MAX_WINDOWS: u64 = 256;


pub const MAX_MATCHERS: u64 = 16;


pub const MAX_ASSETS: u64 = 256;


pub const MAX_VALUE_LEN: u64 = 256;


pub const MAX_REGEX_LEN: u64 = 256;


pub const MAX_REGEX_BYTES: usize = 65_536;


pub const MAX_TEXT_LEN: u64 = 512;


pub const MAX_ALERTS: u64 = 10_000;


pub const MAX_GROUP_LABELS: u64 = 8;


pub const MAX_CHANNELS: u64 = 64;


pub const MAX_TARGET_LEN: u64 = 2048;


pub const MAX_PATH_LEN: u64 = 4096;


pub const MAX_RENDER_ENTRIES: usize = 32;


pub const MAX_REASON_LEN: usize = 256;


pub const SMTP_SUBJECT_LEN: usize = 200;


pub const SMTP_BODY_LEN: usize = 8_000;


pub const WEBHOOK_SUBJECT_LEN: usize = 200;


pub const WEBHOOK_BODY_LEN: usize = 4_000;


pub const NTFY_SUBJECT_LEN: usize = 100;


pub const NTFY_BODY_LEN: usize = 1_000;


pub const TEAMS_SUBJECT_LEN: usize = 150;


pub const TEAMS_BODY_LEN: usize = 4_000;


pub const SLACK_SUBJECT_LEN: usize = 150;


pub const SLACK_BODY_LEN: usize = 3_000;


pub const SMS_SUBJECT_LEN: usize = 40;


pub const SMS_BODY_LEN: usize = 160;


pub const MAX_SECRET_BYTES: u64 = 4096;


pub const MAX_TIMEOUT_MILLIS: u64 = 60_000;


pub const MAX_SECRET_DIRS: u64 = 1024;


pub const MAX_HOST_LEN: u64 = 253;


pub const MAX_USERNAME_LEN: u64 = MAX_VALUE_LEN;


pub const UTF8_MAX_BYTES: usize = 4;


pub const MAX_MAIL_SUBJECT_BYTES: usize = SMTP_SUBJECT_LEN * UTF8_MAX_BYTES;


pub const MAX_MAIL_BODY_BYTES: usize = SMTP_BODY_LEN * UTF8_MAX_BYTES;


pub const MAX_REPLY_LINE_BYTES: usize = 512;


pub const MAX_REPLY_BYTES: usize = 4096;


pub const READ_CHUNK_BYTES: usize = 512;


pub const WRITE_CHUNK_BYTES: usize = 1024;


pub const MAX_IO_STEPS: usize = 4096;


pub const MAX_CONNECT_ADDRESSES: usize = 8;


pub const MAX_ALERT_LEVEL: u32 = 10;


pub const MAX_FINGERPRINT_BYTES: usize = 256;


pub const MAX_OPEN_ALERTS: u32 = 1000;


pub const MAX_CHANNEL_NAME_BYTES: usize = 64;


pub const LINK_LIFETIME_SECONDS: i64 = 86_400;


pub const LINK_SKEW_SECONDS: i64 = 300;


pub const NONCE_BYTES: usize = 16;


pub const MAC_BYTES: usize = 32;


pub const MIN_LINK_KEY_BYTES: usize = 32;


pub const MAX_LINK_KEY_BYTES: u64 = 1024;


pub const MAX_TOKEN_CHARS: usize = 192;


pub const LINK_ACTION_ACKNOWLEDGE: u8 = 1;


pub const LINK_ACTION_RESOLVE: u8 = 2;


pub const MAX_SOURCE_TENANTS: u64 = 256;


pub const MAX_SOURCE_INTERVAL_SECONDS: u64 = 3600;


pub const SEVERITY_COUNT: usize = 5;


pub const MAX_SOURCE_TEXT_CHARS: usize = 256;


/// Outbox rows of unpolled tenants dropped per round.
pub const MAX_PURGE_PER_ROUND: usize = 1000;


/// Outbox rows older than a tenant's `added_at` consumed per poll.
pub const MAX_SKIP_PER_POLL: usize = 1000;


/// The poller lease lasts this many intervals.
pub const LEASE_FACTOR: u64 = 3;


/// Longest poller id, characters.
pub const MAX_HOLDER_CHARS: usize = 64;


/// Random bytes (hex-encoded in the id) that make each process's poller id its own.
pub const HOLDER_RANDOM_BYTES: usize = 8;


/// The server cancels a purge after this many milliseconds (`core_pg::query::timed_script`), before the client deadline gives up and before the shortest lease (`LEASE_FACTOR` seconds).
pub const PURGE_SERVER_TIMEOUT_MILLIS: u64 = 2_000;


/// Client deadline of a purge, milliseconds: always above `PURGE_SERVER_TIMEOUT_MILLIS`, so the server cancels first and nothing commits after the client gave up.
pub const PURGE_CLIENT_DEADLINE_MILLIS: u64 = 5_000;
