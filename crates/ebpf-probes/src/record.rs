//! Records shared with the kernel programs; the byte layouts are listed in the crate rules file.

use std::io::Read;


pub const EXEC_RECORD_BYTES: usize = 40;


pub const COMM_BYTES: usize = 16;


pub const WORD_BYTES: usize = 4;


pub const FILE_RECORD_KIND: u32 = 3;


pub const FILE_HEADER_WORDS: usize = 12;


pub const FILE_PATH_BYTES: usize = 256;


pub const FILE_RECORD_BYTES: usize = FILE_HEADER_WORDS * WORD_BYTES + FILE_PATH_BYTES;


pub const STATUS_TOO_LONG: u32 = 1;


pub const STATUS_PATH_ERROR: u32 = 2;


pub const STATUS_UNLINKED: u32 = 4;


pub const RECORD_WORDS: usize = EXEC_RECORD_BYTES / WORD_BYTES;


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExecRecord {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub monotonic_ns: u64,
    pub comm: String,
}


#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FileRecord {
    pub pid: u32,
    pub uid: u32,
    pub flags: u32,
    pub mode: u32,
    pub too_long: bool,
    pub path_error: bool,
    pub unlinked: bool,
    pub monotonic_ns: u64,
    pub device: u32,
    pub inode: u64,
    pub mount_namespace: u32,
    pub path: String,
}


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    WrongSize { got: usize },
    FileWrongSize { got: usize },
    FileWrongKind { got: u32 },
    FileUnknownStatus { got: u32 },
}


impl std::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::WrongSize { got } => write!(formatter, "exec record has {got} bytes, expected {EXEC_RECORD_BYTES}"),
            DecodeError::FileWrongSize { got } => write!(formatter, "file record has {got} bytes, expected {FILE_RECORD_BYTES}"),
            DecodeError::FileWrongKind { got } => write!(formatter, "file record has kind {got}, expected {FILE_RECORD_KIND}"),
            DecodeError::FileUnknownStatus { got } => write!(formatter, "file record has unknown status bits {got}"),
        }
    }
}


impl std::error::Error for DecodeError {}


/// Decodes one exec record; the comm is cut at the first NUL and every byte outside printable ASCII is escaped as `\xNN`.
pub fn decode_exec(bytes: &[u8]) -> Result<ExecRecord, DecodeError> {
    let wrong_size = DecodeError::WrongSize { got: bytes.len() };
    let mut rest = bytes;
    let mut words = [[0u8; WORD_BYTES]; RECORD_WORDS];
    words.iter_mut().try_for_each(|word| rest.read_exact(word)).map_err(|_| wrong_size)?;
    let [pid, ppid, uid, gid, ns_low, ns_high, comm_0, comm_1, comm_2, comm_3] = words;
    let monotonic_ns = u64::from(u32::from_le_bytes(ns_low)) | (u64::from(u32::from_le_bytes(ns_high)) << u32::BITS);
    let record = ExecRecord {
        pid: u32::from_le_bytes(pid),
        ppid: u32::from_le_bytes(ppid),
        uid: u32::from_le_bytes(uid),
        gid: u32::from_le_bytes(gid),
        monotonic_ns,
        comm: escape_comm(&[comm_0, comm_1, comm_2, comm_3].concat()),
    };
    if rest.is_empty() {
        Ok(record)
    } else {
        Err(wrong_size)
    }
}


/// Cuts at the first NUL and escapes every byte outside printable ASCII (space counts as printable; a backslash is escaped too, so the output is unambiguous).
pub fn escape_comm(raw: &[u8]) -> String {
    raw.iter().take_while(|byte| **byte != 0).map(|byte| escape_byte(*byte)).collect()
}


fn escape_byte(byte: u8) -> String {
    if (byte.is_ascii_graphic() || byte == b' ') && byte != b'\\' {
        char::from(byte).to_string()
    } else {
        format!("\\x{byte:02x}")
    }
}


/// Decodes one file-open record: any other length, kind or status bit is refused by name; the path is cut at its first NUL and escaped as `escape_comm` does; the kernel zeroes the path field when it flags `too_long` or `path_error`.
pub fn decode_file(bytes: &[u8]) -> Result<FileRecord, DecodeError> {
    let wrong_size = DecodeError::FileWrongSize { got: bytes.len() };
    let mut rest = bytes;
    let mut words = [[0u8; WORD_BYTES]; FILE_HEADER_WORDS];
    words.iter_mut().try_for_each(|word| rest.read_exact(word)).map_err(|_| wrong_size)?;
    let [kind, pid, uid, flags, mode, status, ns_low, ns_high, device, ino_low, ino_high, mount_namespace] = words.map(u32::from_le_bytes);
    (rest.len() == FILE_PATH_BYTES).then_some(()).ok_or(wrong_size)?;
    let known_status = STATUS_TOO_LONG | STATUS_PATH_ERROR | STATUS_UNLINKED;
    (kind == FILE_RECORD_KIND).then_some(()).ok_or(DecodeError::FileWrongKind { got: kind })?;
    (status & !known_status == 0)
        .then_some(())
        .ok_or(DecodeError::FileUnknownStatus { got: status })?;
    Ok(FileRecord {
        pid,
        uid,
        flags,
        mode,
        too_long: status & STATUS_TOO_LONG != 0,
        path_error: status & STATUS_PATH_ERROR != 0,
        unlinked: status & STATUS_UNLINKED != 0,
        monotonic_ns: u64::from(ns_low) | (u64::from(ns_high) << u32::BITS),
        device,
        inode: u64::from(ino_low) | (u64::from(ino_high) << u32::BITS),
        mount_namespace,
        path: escape_comm(rest),
    })
}


/// The kernel time of an exec record, for the limiter.
pub fn exec_time(record: &ExecRecord) -> u64 {
    record.monotonic_ns
}


/// The kernel time of a file record, for the limiter.
pub fn file_time(record: &FileRecord) -> u64 {
    record.monotonic_ns
}
