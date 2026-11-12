use crate::listen_model::ListenerKind;


pub const CURSOR_FILE: &str = "forward.cursor";


pub const CURSOR_TEMPORARY: &str = "forward.cursor.tmp";


pub const CURSOR_MAX_BYTES: u64 = 32;


pub const MAX_FORWARD_BATCH_RECORDS: usize = 1000;


pub const MAX_AGENT_SPOOL_BYTES: u64 = 64 * 1024 * 1024;


pub const MAX_FORWARD_MESSAGE_BYTES: usize = 1024;


pub const MAX_FORWARD_HOST_BYTES: usize = 253;


pub const MAX_RAW_HOST_BYTES: usize = 64;


pub const UNKNOWN_FACILITY: &str = "unknown";


pub const MODULE: &str = "syslog";


pub const FACILITY_NAMES: &[&str] = &[
    "kern", "user", "mail", "daemon", "auth", "syslog", "lpr", "news", "uucp", "cron", "authpriv", "ftp", "ntp", "audit", "alert", "clock", "local0",
    "local1", "local2", "local3", "local4", "local5", "local6", "local7",
];


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ForwardLimits {
    pub kind: ListenerKind,
    pub max_records: usize,
    pub agent_spool_max_bytes: u64,
}


#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ForwardReport {
    pub forwarded: u64,
    pub skipped_unparsable: u64,
    pub skipped_unknown_version: u64,
    pub refused_full: u64,
}


pub const EPOCH_FILE: &str = "spool.epoch";


pub const EPOCH_TEMPORARY: &str = "spool.epoch.tmp";


pub const EPOCH_BYTES: usize = 16;
