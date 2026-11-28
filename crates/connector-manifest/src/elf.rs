use crate::error::ConnectorError;


pub const ELF_MAGIC: &[u8] = b"\x7fELF";


pub const CLASS_OFFSET: usize = 4;


pub const DATA_OFFSET: usize = 5;


pub const CLASS_64: u8 = 2;


pub const LITTLE_ENDIAN: u8 = 1;


pub const PROGRAM_OFFSET_FIELD: usize = 32;


pub const PROGRAM_OFFSET_WIDTH: usize = 8;


pub const ENTRY_SIZE_FIELD: usize = 54;


pub const COUNT_FIELD: usize = 56;


pub const SHORT_WIDTH: usize = 2;


pub const TYPE_WIDTH: usize = 4;


pub const MIN_ENTRY_SIZE: u64 = 56;


pub const PT_INTERP: u64 = 3;


pub const BITS_PER_BYTE: u32 = 8;


fn unsupported(reason: &'static str) -> ConnectorError {
    ConnectorError::UnsupportedEntry { reason }
}


/// `width` little-endian bytes at `offset`, `None` when the buffer ends first.
pub fn read_le(bytes: &[u8], offset: u64, width: usize) -> Option<u64> {
    let start = usize::try_from(offset).unwrap_or(usize::MAX);
    bytes
        .get(start..)
        .and_then(|rest| rest.get(..width))
        .map(|field| field.iter().rev().fold(0, |value, byte| (value << BITS_PER_BYTE) | u64::from(*byte)))
}


pub fn byte_at(bytes: &[u8], offset: usize) -> Option<u8> {
    bytes.get(offset).copied()
}


/// A little-endian 64-bit ELF file: anything else (a `#!` script, another class) is not a native connector.
pub fn check_header(bytes: &[u8]) -> Result<(), ConnectorError> {
    bytes
        .starts_with(ELF_MAGIC)
        .then_some(())
        .ok_or(unsupported("the entry is not an ELF file"))?;
    (byte_at(bytes, CLASS_OFFSET) == Some(CLASS_64) && byte_at(bytes, DATA_OFFSET) == Some(LITTLE_ENDIAN))
        .then_some(())
        .ok_or(unsupported("the entry is not a little-endian 64-bit ELF file"))
}


/// A native entry is a static ELF: a `PT_INTERP` header (a dynamic loader chosen by the file) is refused, judged on the copied bytes.
pub fn check_static_elf(bytes: &[u8]) -> Result<(), ConnectorError> {
    check_header(bytes)?;
    let ((table, entry_size), count) = read_le(bytes, PROGRAM_OFFSET_FIELD as u64, PROGRAM_OFFSET_WIDTH)
        .zip(read_le(bytes, ENTRY_SIZE_FIELD as u64, SHORT_WIDTH))
        .zip(read_le(bytes, COUNT_FIELD as u64, SHORT_WIDTH))
        .ok_or(unsupported("the ELF header is truncated"))?;
    (entry_size >= MIN_ENTRY_SIZE)
        .then_some(())
        .ok_or(unsupported("the ELF program header size is wrong"))?;
    let interpreter = (0..count).try_fold(false, |found, index| {
        read_le(bytes, table.saturating_add(index * entry_size), TYPE_WIDTH)
            .map(|kind| found || kind == PT_INTERP)
            .ok_or(unsupported("the ELF program headers are truncated"))
    })?;
    (!interpreter)
        .then_some(())
        .ok_or(unsupported("the ELF names a dynamic loader (PT_INTERP)"))
}
