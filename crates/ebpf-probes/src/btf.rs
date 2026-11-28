//! Byte offsets of `task_struct.real_parent` and `task_struct.tgid` read from the kernel BTF.

use crate::types::{Lookup, Member, Parsed, Resolved, Rule, Walked};
use std::fs::File;
use std::io::{ErrorKind, Read};
use std::ops::ControlFlow;
use std::path::Path;


pub const VMLINUX_BTF_PATH: &str = "/sys/kernel/btf/vmlinux";


pub const MAX_BTF_BYTES: u64 = 32 * 1024 * 1024;


pub const MAX_BTF_TYPES: usize = 1024 * 1024;


pub const BITS_PER_BYTE: u32 = 8;


pub const REAL_PARENT_BYTES: u32 = 8;


pub const TGID_BYTES: u32 = 4;


pub const MAX_TYPE_CHAIN: u32 = 16;


const INT_BITS_MASK: u32 = 0xff;


const INT_OFFSET_SHIFT: u32 = 16;


const INT_OFFSET_MASK: u32 = 0xff;


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


pub const REASON_MEMBER_TYPE: &str = "task_struct member has an unexpected type";


pub const REASON_TYPE_CHAIN: &str = "task_struct member type chain is too long or loops";


pub const REASON_OUT_OF_STRUCT: &str = "task_struct member lies outside the struct";


pub const REASON_NOT_64_BIT: &str = "the probe supports 64-bit hosts only (a pointer is read as 8 bytes)";


pub const POINTER_BITS: u32 = 64;


#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskOffsets {
    pub real_parent: u32,
    pub tgid: u32,
}


/// Where the task_struct body sits in the type section.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TaskStruct {
    pub body: usize,
    pub count: usize,
    pub flagged: bool,
    pub size: u32,
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


/// Refuses a host whose pointers are not 8 bytes: `REAL_PARENT_BYTES` assumes it.
pub fn require_64_bit(pointer_bits: u32) -> Result<(), Unsupported> {
    if pointer_bits == POINTER_BITS {
        Ok(())
    } else {
        Err(Unsupported(REASON_NOT_64_BIT))
    }
}


/// Opens the BTF file once and reads the offsets from that handle.
pub fn read_task_offsets(path: &Path) -> Result<TaskOffsets, Unsupported> {
    let file = open_btf(path)?;
    read_task_offsets_from(file)
}


/// Opens the BTF file, mapping a failure to a fixed reason.
pub fn open_btf(path: &Path) -> Result<File, Unsupported> {
    File::open(path).map_err(open_error)
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
    let data = read_btf_bytes(reader)?;
    find_task_offsets(&data)
}


/// Reads at most `MAX_BTF_BYTES` from the reader, refusing anything longer.
pub fn read_btf_bytes<Source: Read>(reader: Source) -> Result<Vec<u8>, Unsupported> {
    let mut data = Vec::new();
    reader
        .take(MAX_BTF_BYTES + 1)
        .read_to_end(&mut data)
        .map_err(|_| Unsupported(REASON_UNREADABLE))?;
    if data.len() as u64 > MAX_BTF_BYTES {
        Err(Unsupported(REASON_OVERSIZED))
    } else {
        Ok(data)
    }
}


/// Walks the type section of raw BTF bytes, looking at no more than `MAX_BTF_TYPES` types.
pub fn find_task_offsets(data: &[u8]) -> Result<TaskOffsets, Unsupported> {
    let parsed = parse_structs(data, &[STRUCT_NAME])?;
    let task = parsed.found.first().copied().flatten().ok_or(Unsupported(REASON_NO_TASK_STRUCT))?;
    task_offsets(&lookup_of(&parsed), &task)
}


/// Walks the type section once and records the first STRUCT of each wanted name.
pub fn parse_structs<'a>(data: &'a [u8], names: &[&str]) -> Result<Parsed<'a>, Unsupported> {
    let [first, header_len, type_off, type_len, str_off, str_len] = read_words::<HEADER_WORDS>(data, 0)?;
    check_header(first, header_len)?;
    let types = section(data, header_len, type_off, type_len)?;
    let strings = section(data, header_len, str_off, str_len)?;
    let mut position = 0;
    let mut steps = 0;
    let mut found = vec![None; names.len()];
    let mut duplicated = vec![false; names.len()];
    let mut index = Vec::new();
    while position < types.len() && steps < MAX_BTF_TYPES {
        let (next, matched) = walk_type(types, strings, position, names)?;
        index.push(position);
        position = next;
        record_match(&mut found, &mut duplicated, matched);
        steps += 1;
    }
    walk_complete(position, types.len())?;
    Ok(Parsed {
        types,
        strings,
        index,
        found,
        duplicated,
    })
}


/// The lookup tables of a parsed type section.
pub fn lookup_of<'a>(parsed: &'a Parsed<'a>) -> Lookup<'a> {
    Lookup {
        types: parsed.types,
        strings: parsed.strings,
        index: &parsed.index,
    }
}


fn record_match(found: &mut [Option<TaskStruct>], duplicated: &mut [bool], matched: Option<(usize, TaskStruct)>) {
    matched.iter().for_each(|(which, body)| {
        found
            .iter_mut()
            .zip(duplicated.iter_mut())
            .skip(*which)
            .take(1)
            .for_each(|(slot, repeat)| {
                *repeat = slot.is_some();
                *slot = slot.or(Some(*body));
            });
    });
}


fn walk_complete(position: usize, length: usize) -> Result<(), Unsupported> {
    if position > length {
        Err(Unsupported(REASON_TRUNCATED))
    } else if position < length {
        Err(Unsupported(REASON_TOO_MANY_TYPES))
    } else {
        Ok(())
    }
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
    let bounds = usize::try_from(start).ok().zip(usize::try_from(end).ok());
    bounds.and_then(|(from, to)| data.get(from..to)).ok_or(Unsupported(REASON_TRUNCATED))
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


fn walk_type(types: &[u8], strings: &[u8], position: usize, names: &[&str]) -> Result<Walked, Unsupported> {
    let [name_offset, info, size_or_type] = read_words::<TYPE_WORDS>(types, position)?;
    let kind = (info >> KIND_SHIFT) & KIND_MASK;
    let count = (info & VLEN_MASK) as usize;
    let body = position + TYPE_BYTES;
    let next = body + extra_bytes(kind, count)?;
    let which = names
        .iter()
        .position(|name| name_is(strings, name_offset, name))
        .filter(|_| kind == KIND_STRUCT);
    let flagged = info >> KIND_FLAG_SHIFT == 1;
    let task = TaskStruct {
        body,
        count,
        flagged,
        size: size_or_type,
    };
    Ok((next, which.map(|slot| (slot, task))))
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


fn task_offsets(lookup: &Lookup, task: &TaskStruct) -> Result<TaskOffsets, Unsupported> {
    let members = members_of(lookup.types, task);
    let real_parent = member_offset(lookup, &members, task, (REAL_PARENT_NAME, REASON_NO_REAL_PARENT), Rule::Pointer)?;
    let tgid = member_offset(lookup, &members, task, (TGID_NAME, REASON_NO_TGID), Rule::Int(TGID_BYTES))?;
    Ok(TaskOffsets { real_parent, tgid })
}


/// The member records of a struct body; the walk proved each one readable.
pub fn members_of(types: &[u8], task: &TaskStruct) -> Vec<Member> {
    (0..task.count)
        .flat_map(|i| read_words::<MEMBER_WORDS>(types, task.body + i * MEMBER_BYTES))
        .collect::<Vec<Member>>()
}


/// The byte offset of a named member whose type matches the rule.
pub fn member_offset(lookup: &Lookup, members: &[Member], task: &TaskStruct, name: (&str, &'static str), required: Rule) -> Result<u32, Unsupported> {
    member_resolved(lookup, members, task, name, required).map(|(byte_offset, _)| byte_offset)
}


/// The offset of an embedded STRUCT member and the body of the type that member resolves to, never a struct found by name.
pub fn member_struct(
    lookup: &Lookup,
    members: &[Member],
    task: &TaskStruct,
    name: (&str, &'static str),
    nested: &'static str,
) -> Result<(u32, TaskStruct), Unsupported> {
    let (byte_offset, resolved) = member_resolved(lookup, members, task, name, Rule::Struct(nested))?;
    let [_, info, size] = read_words::<TYPE_WORDS>(lookup.types, resolved.1)?;
    let body = TaskStruct {
        body: resolved.1 + TYPE_BYTES,
        count: (info & VLEN_MASK) as usize,
        flagged: info >> KIND_FLAG_SHIFT == 1,
        size,
    };
    Ok((byte_offset, body))
}


fn member_resolved(
    lookup: &Lookup,
    members: &[Member],
    task: &TaskStruct,
    name: (&str, &'static str),
    required: Rule,
) -> Result<(u32, Resolved), Unsupported> {
    let member = members.iter().find(|&&[name_offset, _, _]| name_is(lookup.strings, name_offset, name.0));
    let [_, type_id, raw] = member.ok_or(Unsupported(name.1))?;
    let (bit_offset, bitfield_size) = if task.flagged {
        (raw & BIT_OFFSET_MASK, raw >> BITFIELD_SHIFT)
    } else {
        (*raw, 0)
    };
    let byte_offset = bit_offset / BITS_PER_BYTE;
    let aligned = bitfield_size == 0 && bit_offset % BITS_PER_BYTE == 0;
    let resolved = resolve_type(lookup, *type_id)?;
    let field_bytes = type_bytes(lookup.types, resolved)?;
    let fits = byte_offset.checked_add(field_bytes).is_some_and(|end| end <= task.size);
    if !aligned {
        Err(Unsupported(REASON_BITFIELD))
    } else if !rule_matches(lookup, resolved, field_bytes, required) {
        Err(Unsupported(REASON_MEMBER_TYPE))
    } else if !fits {
        Err(Unsupported(REASON_OUT_OF_STRUCT))
    } else {
        Ok((byte_offset, resolved))
    }
}


fn rule_matches(lookup: &Lookup, resolved: Resolved, bytes: u32, rule: Rule) -> bool {
    let (kind, position) = resolved;
    match rule {
        Rule::Int(size) => kind == KIND_INT && bytes == size,
        Rule::Pointer => kind == KIND_PTR,
        Rule::Struct(name) => {
            kind == KIND_STRUCT
                && read_words::<TYPE_WORDS>(lookup.types, position).is_ok_and(|[name_offset, _, _]| name_is(lookup.strings, name_offset, name))
        }
    }
}


fn type_position(lookup: &Lookup, id: u32) -> Result<usize, Unsupported> {
    let slot = usize::try_from(id).ok().and_then(|number| number.checked_sub(1));
    slot.and_then(|position| lookup.index.get(position))
        .copied()
        .ok_or(Unsupported(REASON_MEMBER_TYPE))
}


fn resolve_type(lookup: &Lookup, id: u32) -> Result<Resolved, Unsupported> {
    let outcome = (0..MAX_TYPE_CHAIN).try_fold(id, |current, _| resolve_step(lookup, current));
    match outcome {
        ControlFlow::Break(result) => result,
        ControlFlow::Continue(_) => Err(Unsupported(REASON_TYPE_CHAIN)),
    }
}


fn resolve_step(lookup: &Lookup, current: u32) -> ControlFlow<Result<Resolved, Unsupported>, u32> {
    let step = type_position(lookup, current).and_then(|position| {
        read_words::<TYPE_WORDS>(lookup.types, position).map(|[_, info, target]| (position, (info >> KIND_SHIFT) & KIND_MASK, target))
    });
    match step {
        Err(error) => ControlFlow::Break(Err(error)),
        Ok((_, KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT, target)) => ControlFlow::Continue(target),
        Ok((position, kind, _)) => ControlFlow::Break(Ok((kind, position))),
    }
}


fn type_bytes(types: &[u8], resolved: Resolved) -> Result<u32, Unsupported> {
    let (kind, position) = resolved;
    match kind {
        KIND_PTR => Ok(REAL_PARENT_BYTES),
        KIND_INT => int_bytes(types, position),
        KIND_STRUCT => struct_bytes(types, position),
        _ => Err(Unsupported(REASON_MEMBER_TYPE)),
    }
}


fn int_bytes(types: &[u8], position: usize) -> Result<u32, Unsupported> {
    let [_, _, size] = read_words::<TYPE_WORDS>(types, position)?;
    let [int_word] = read_words::<1>(types, position + TYPE_BYTES)?;
    let int_bits = int_word & INT_BITS_MASK;
    let int_offset = (int_word >> INT_OFFSET_SHIFT) & INT_OFFSET_MASK;
    if int_offset == 0 && int_bits == size.saturating_mul(BITS_PER_BYTE) {
        Ok(size)
    } else {
        Err(Unsupported(REASON_BITFIELD))
    }
}


fn struct_bytes(types: &[u8], position: usize) -> Result<u32, Unsupported> {
    let [_, _, size] = read_words::<TYPE_WORDS>(types, position)?;
    Ok(size)
}
