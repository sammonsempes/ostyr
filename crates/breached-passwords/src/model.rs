use std::fs::File;
use zeroize::Zeroizing;


pub const HASH_BYTES: usize = 16;


pub const HASH_HEX_LEN: usize = 32;


pub const MAX_LINE_BYTES: usize = 128;


pub const MAX_LIST_LINES: u64 = 4_000_000_000;


pub const SCAN_BUFFER_BYTES: usize = 65_536;


pub const WRITE_BITS: u32 = 0o022;


pub const FILE_SHARE_READ: u32 = 1;


pub const DECIMAL_BASE: u32 = 10;


pub const MAX_HASH_FILE_BYTES: u64 = 4_194_304;


pub const MAX_HASHES: usize = 100_000;


/// An NT hash: password-equivalent, zeroed on drop, and deliberately without `Debug` or `Display`.
#[derive(Clone)]
pub struct NtHash(pub Zeroizing<[u8; HASH_BYTES]>);


/// The answer for one hash: whether the list holds it. No prevalence count: it is public and would identify the list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub compromised: bool,
}


/// The result of the whole pass: the lines, the SHA-256 of the bytes read in lowercase hex, and a found flag per sorted key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scanned {
    pub lines: u64,
    pub sha256: String,
    pub found: Vec<bool>,
}


/// What `fstat` of the open handle says: device, inode, size, write time and change time (with nanoseconds); any difference is a change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileIdentity {
    pub device: u64,
    pub inode: u64,
    pub size: u64,
    pub written: i64,
    pub written_nsec: i64,
    pub changed: i64,
    pub changed_nsec: i64,
}


/// A list opened once and checked whole, with the size and identity seen at that moment, its line count, SHA-256 and one verdict per target in input order.
#[derive(Debug)]
pub struct BreachedList {
    pub file: File,
    pub size: u64,
    pub identity: FileIdentity,
    pub lines: u64,
    pub sha256: String,
    pub verdicts: Vec<Verdict>,
}
