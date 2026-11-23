//! Exec record shared with the kernel program: little-endian `pid u32, ppid u32, uid u32, gid u32, monotonic_ns u64, comm [u8; 16]`.

use std::io::Read;


pub const EXEC_RECORD_BYTES: usize = 40;


pub const COMM_BYTES: usize = 16;


pub const WORD_BYTES: usize = 4;


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


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DecodeError {
    WrongSize { got: usize },
}


impl std::fmt::Display for DecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeError::WrongSize { got } => write!(formatter, "exec record has {got} bytes, expected {EXEC_RECORD_BYTES}"),
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
