use agent_channel::commands::MAX_COMMAND_FILES;


/// Lifetime of one routine envelope, below `agent_command::model::MAX_LIFETIME_SECONDS`.
pub const LIFETIME_SECONDS: u64 = 300;


/// Routine commands issued beyond `confirmed` before the issue refuses, under `MAX_SEQUENCE_ADVANCE`.
pub const MAX_UNCONFIRMED: u64 = 900;


pub const MAX_AGENTS_PER_TENANT: u64 = 10_000;


/// Every entry of an agent directory counts, so a hostile directory cannot make a listing unbounded.
pub const MAX_QUEUE_SCAN_ENTRIES: usize = 2 * MAX_COMMAND_FILES;


pub const MAX_STAGING_SCAN_ENTRIES: usize = 1_024;


pub const SEED_READ_LIMIT: u64 = 66;


pub const SEED_READ_CAPACITY: usize = 66;


pub const SEED_HEX_BYTES: usize = 64;


pub const SEED_BYTES: usize = 32;


pub const STAGING_NAME: &str = ".staging";


pub const STAGING_NAME_BYTES: usize = 16;


pub const FILE_MODE: u32 = 0o640;


pub const STAGING_MODE: u32 = 0o700;


pub const AGENT_DIRECTORY_MODE: u32 = 0o750;


pub const GROUP_OTHER_WRITE: u32 = 0o022;


pub const NAME_DIGITS: usize = 20;


pub const ENVELOPE_SUFFIX: &str = ".env";


pub const ROUTINE_ACTIONS: [&str; 2] = ["ping", "collect_status"];


/// The caps one issue runs under; tests inject small ones.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_unconfirmed: u64,
    pub max_agents: u64,
    pub max_queue_files: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_unconfirmed: MAX_UNCONFIRMED,
            max_agents: MAX_AGENTS_PER_TENANT,
            max_queue_files: MAX_COMMAND_FILES,
        }
    }
}
