#[cfg(unix)]
pub const TWO_MESSAGES: usize = 2;


#[cfg(unix)]
pub const FOUR_FIELDS: usize = 4;


#[cfg(unix)]
pub const BIG_STRING_BYTES: usize = 300_000;


#[cfg(unix)]
pub const KIB: usize = 1_024;


pub const PROMPT_TOKENS: u32 = 11;


pub const COMPLETION_TOKENS: u32 = 3;


#[cfg(unix)]
pub const LONG_KEY_BYTES: usize = 5_000;


#[cfg(unix)]
pub const KEY_MODE: u32 = 0o600;


#[cfg(unix)]
pub const OPEN_MODE: u32 = 0o644;


pub const SMALL_CAP: usize = 10;


#[cfg(unix)]
pub const STATUS_SERVER_ERROR: u16 = 500;


#[cfg(unix)]
pub const INVALID_UTF8: [u8; 2] = [0xff, 0xfe];


pub const SEPARATORS_COUNTED: usize = 2;


pub const STATE_FIELDS: usize = 10;
