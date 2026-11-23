//! Byte offsets of `task_struct.real_parent` and `task_struct.tgid` read from the kernel BTF.

use crate::types::{Member, Walked};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;


pub const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";


pub const MAX_BTF_BYTES: u64 = 32 * 1024 * 1024;


pub const MAX_BTF_TYPES: usize = 1024 * 1024;


pub const BITS_PER_BYTE: u32 = 8;


pub const REAL_PARENT_BYTES: u32 = 8;


pub const TGID_BYTES: u32 = 4;


const WORD_BYTES: usize = 4;


const HEADER_WORDS: usize = 6;


const HEADER_FIRST_WORD: u32 = 0x0001_EB9F;


const MIN_HEADER_BYTES: u32 = 24;


const TYPE_WORDS: usize = 3;


const TYPE_BYTES: usize = TYPE_WORDS * WORD_BYTES;


pub const MEMBER_WORDS: usize = 3;


const MEMBER_BYTES: usize = MEMBER_WORDS * WORD_BYTES;


const ENUM_VALUE_BYTES: usize = 8;


const PARAM_BYTES: usize = 8;


const ARRAY_BYTES: usize = 12;


const INFO_BYTES: usize = 4;


const VLEN_MASK: u32 = 0xffff;


const KIND_SHIFT: u32 = 24;


const KIND_MASK: u32 = 0x1f;


const KIND_FLAG_SHIFT: u32 = 31;


const BITFIELD_SHIFT: u32 = 24;


const BIT_OFFSET_MASK: u32 = 0x00ff_ffff;


const KIND_INT: u32 = 1;


const KIND_PTR: u32 = 2;


const KIND_ARRAY: u32 = 3;


const KIND_STRUCT: u32 = 4;


const KIND_UNION: u32 = 5;


const KIND_ENUM: u32 = 6;


const KIND_FWD: u32 = 7;


const KIND_TYPEDEF: u32 = 8;


const KIND_VOLATILE: u32 = 9;


const KIND_CONST: u32 = 10;


const KIND_RESTRICT: u32 = 11;


const KIND_FUNC: u32 = 12;


const KIND_FUNC_PROTO: u32 = 13;


const KIND_VAR: u32 = 14;


const KIND_DATASEC: u32 = 15;


const KIND_FLOAT: u32 = 16;


const KIND_DECL_TAG: u32 = 17;


const KIND_TYPE_TAG: u32 = 18;


const KIND_ENUM64: u32 = 19;


const STRUCT_NAME: &str = "task_struct";


const REAL_PARENT_NAME: &str = "real_parent";


const TGID_NAME: &str = "tgid";


pub const REASON_MISSING: &str = "BTF file is missing";


pub const REASON_UNREADABLE: &str = "BTF file cannot be read";


pub const REASON_OVERSIZED: &str = "BTF file is larger than the limit";


pub const REASON_TRUNCATED: &str = "BTF data is truncated or malformed";


pub const REASON_NOT_BTF: &str = "BTF header is not little-endian version 1";


pub const REASON_UNKNOWN_KIND: &str = "BTF holds a type kind this reader cannot skip";


pub const REASON_TOO_MANY_TYPES: &str = "BTF holds more types than the limit";


pub const REASON_NO_TASK_STRUCT: &str = "BTF has no task_struct";


pub const REASON_NO_REAL_PARENT: &str = "task_struct has no real_parent member";


pub const REASON_NO_TGID: &str = "task_struct has no tgid member";


pub const REASON_BITFIELD: &str = "task_struct member is a bitfield or not byte aligned";


pub const REASON_OUT_OF_STRUCT: &str = "task_struct member lies outside the struct";


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskOffsets {
    pub real_parent: u32,
    pub tgid: u32,
}


/// The capability is not available; the reason is fixed text and never holds file bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Unsupported(pub &'static str);


impl std::fmt::Display for Unsupported {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "task offsets unsupported: {}", self.0)
    }
}


impl std::error::Error for Unsupported {}


/// Opens the BTF file once and reads the offsets from that handle.
pub fn read_task_offsets(path: &Path) -> Result<TaskOffsets, Unsupported> {
    let file = File::open(path).map_err(open_error)?;
    read_task_offsets_from(file)
}


fn open_error(error: std::io::Error) -> Unsupported {
    Unsupported(if error.kind() == ErrorKind::NotFound {
        REASON_MISSING
    } else {
        REASON_UNREADABLE
    })
}


/// Reads at most `MAX_BTF_BYTES` from the reader, refusing anything longer.
pub fn read_task_offsets_from<Source: Read>(reader: Source) -> Result<TaskOffsets, Unsupported> {
    let mut data = Vec::new();
    reader
        .take(MAX_BTF_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|_| Unsupported(REASON_UNREADABLE))?;
    if data.len() as u64 > MAX_BTF_BYTES {
        Err(Unsupported(REASON_OVERSIZED))
    } else {
        find_task_offsets(&data)
    }
}


/// Walks the type section of raw BTF bytes, looking at no more than `MAX_BTF_TYPES` types.
pub fn find_task_offsets(data: &[u8]) -> Result<TaskOffsets, Unsupported> {
    let [first, header_len, type_off, type_len, str_off, str_len] = read_words::<HEADER_WORDS>(data, 0)?;
    check_header(first, header_len)?;
    let types = section(data, header_len, type_off, type_len)?;
    let strings = section(data, header_len, str_off, str_len)?;
    let mut position = 0;
    let mut steps = 0;
    let mut found = None;
    while found.is_none() && position < types.len() && steps < MAX_BTF_TYPES {
        let (next, matched) = walk_type(types, strings, position)?;
        position = next;
        found = matched;
        steps += 1;
    }
    let missing = Unsupported(if position < types.len() {
        REASON_TOO_MANY_TYPES
    } else {
        REASON_NO_TASK_STRUCT
    });
    found.ok_or(missing)
}


fn check_header(first: u32, header_len: u32) -> Result<(), Unsupported> {
    if first == HEADER_FIRST_WORD && header_len >= MIN_HEADER_BYTES {
        Ok(())
    } else {
        Err(Unsupported(REASON_NOT_BTF))
    }
}


fn section(data: &[u8], header_len: u32, offset: u32, length: u32) -> Result<&[u8], Unsupported> {
    let start = u64::from(header_len) + u64::from(offset);
    let end = start + u64::from(length);
    data.get(start as usize..end as usize).ok_or(Unsupported(REASON_TRUNCATED))
}


fn read_words<const WORDS: usize>(data: &[u8], start: usize) -> Result<[u32; WORDS], Unsupported> {
    let mut rest = data.get(start..).ok_or(Unsupported(REASON_TRUNCATED))?;
    let mut words = [[0u8; WORD_BYTES]; WORDS];
    words
        .iter_mut()
        .try_for_each(|word| rest.read_exact(word))
        .map_err(|_| Unsupported(REASON_TRUNCATED))?;
    Ok(words.map(u32::from_le_bytes))
}


fn name_is(strings: &[u8], name_offset: u32, expected: &str) -> bool {
    let tail = strings.get(name_offset as usize..);
    tail.is_some_and(|bytes| bytes.split(|byte| *byte == 0).next() == Some(expected.as_bytes()))
}


fn walk_type(types: &[u8], strings: &[u8], position: usize) -> Result<Walked, Unsupported> {
    let [name_offset, info, size_or_type] = read_words::<TYPE_WORDS>(types, position)?;
    let kind = (info >> KIND_SHIFT) & KIND_MASK;
    let count = (info & VLEN_MASK) as usize;
    let body = position + TYPE_BYTES;
    let next = body + extra_bytes(kind, count)?;
    let is_task = kind == KIND_STRUCT && name_is(strings, name_offset, STRUCT_NAME);
    let flagged = info >> KIND_FLAG_SHIFT == 1;
    let matched = is_task
        .then(|| task_offsets(types, strings, body, count, flagged, size_or_type))
        .transpose()?;
    Ok((next, matched))
}


fn extra_bytes(kind: u32, count: usize) -> Result<usize, Unsupported> {
    match kind {
        KIND_INT | KIND_VAR | KIND_DECL_TAG => Ok(INFO_BYTES),
        KIND_ARRAY => Ok(ARRAY_BYTES),
        KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => Ok(count * MEMBER_BYTES),
        KIND_ENUM => Ok(count * ENUM_VALUE_BYTES),
        KIND_FUNC_PROTO => Ok(count * PARAM_BYTES),
        KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => Ok(0),
        _ => Err(Unsupported(REASON_UNKNOWN_KIND)),
    }
}


fn task_offsets(types: &[u8], strings: &[u8], body: usize, count: usize, flagged: bool, size: u32) -> Result<TaskOffsets, Unsupported> {
    let members = (0..count)
        .map(|i| read_words::<MEMBER_WORDS>(types, body + i * MEMBER_BYTES))
        .collect::<Result<Vec<Member>, _>>()?;
    let real_parent = member_offset(
        &members,
        strings,
        (REAL_PARENT_NAME, REASON_NO_REAL_PARENT),
        flagged,
        (size, REAL_PARENT_BYTES),
    )?;
    let tgid = member_offset(&members, strings, (TGID_NAME, REASON_NO_TGID), flagged, (size, TGID_BYTES))?;
    Ok(TaskOffsets { real_parent, tgid })
}


fn member_offset(members: &[Member], strings: &[u8], name: (&str, &'static str), flagged: bool, field: (u32, u32)) -> Result<u32, Unsupported> {
    let (struct_size, field_bytes) = field;
    let member = members.iter().find(|&&[name_offset, _, _]| name_is(strings, name_offset, name.0));
    let [_, _, raw] = member.ok_or(Unsupported(name.1))?;
    let (bit_offset, bitfield_size) = if flagged {
        (raw & BIT_OFFSET_MASK, raw >> BITFIELD_SHIFT)
    } else {
        (*raw, 0)
    };
    let byte_offset = bit_offset / BITS_PER_BYTE;
    let aligned = bitfield_size == 0 && bit_offset % BITS_PER_BYTE == 0;
    let fits = byte_offset.checked_add(field_bytes).is_some_and(|end| end <= struct_size);
    if !aligned {
        Err(Unsupported(REASON_BITFIELD))
    } else if !fits {
        Err(Unsupported(REASON_OUT_OF_STRUCT))
    } else {
        Ok(byte_offset)
    }
}
