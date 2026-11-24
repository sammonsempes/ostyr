use ebpf_probes::btf::{
    find_task_offsets, read_task_offsets, read_task_offsets_from, TaskOffsets, Unsupported, MAX_BTF_BYTES, MAX_BTF_TYPES, MAX_TYPE_CHAIN,
    REASON_BITFIELD, REASON_MEMBER_TYPE, REASON_MISSING, REASON_NOT_BTF, REASON_NO_REAL_PARENT, REASON_NO_TASK_STRUCT, REASON_NO_TGID,
    REASON_OUT_OF_STRUCT, REASON_OVERSIZED, REASON_TOO_MANY_TYPES, REASON_TRUNCATED, REASON_TYPE_CHAIN, REASON_UNKNOWN_KIND, REASON_UNREADABLE,
};
use ebpf_probes::types::ExtraType;
use std::error::Error;
use std::fs::File;
use std::io::{self, Read};
use std::path::PathBuf;


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


const KIND_FUNC_PROTO: u32 = 13;


const KIND_UNKNOWN: u32 = 20;


const KIND_SHIFT: u32 = 24;


const FLAG_SHIFT: u32 = 31;


const FIRST_WORD: u32 = 0x0001_EB9F;


const HEADER_BYTES: u32 = 24;


const WORD: usize = 4;


const TASK_SIZE: u32 = 4096;


const REAL_PARENT_BITS: u32 = 1024;


const TGID_BITS: u32 = 1280;


const REAL_PARENT_BYTE: u32 = 128;


const TGID_BYTE: u32 = 160;


const REAL_PARENT_FIELD: u32 = 8;


const BITS: u32 = 8;


const BITFIELD_SIZE_SHIFT: u32 = 24;


const THREE_BITS: u32 = 3;


const FORGED_VLEN: u32 = 60000;


const FORGED_NAME_OFFSET: u32 = 0xFFFF;


const SPARSE_BYTES: u64 = 1 << 40;


const HEADER_LEN_WORD: usize = 1;


const TYPE_LEN_WORD: usize = 3;


const STR_OFF_WORD: usize = 4;


const STR_LEN_WORD: usize = 5;


const SHORT_HEADER: u32 = 23;


const INT_TYPE: u32 = 1;


const POINTER_TYPE: u32 = 2;


const ARRAY_TYPE: u32 = 3;


const FIRST_EXTRA_TYPE: u32 = 8;


const CONST_TYPE: u32 = FIRST_EXTRA_TYPE + 1;


const VOLATILE_TYPE: u32 = FIRST_EXTRA_TYPE + 2;


const RESTRICT_TYPE: u32 = FIRST_EXTRA_TYPE + 3;


const POINTER_TYPEDEF: u32 = FIRST_EXTRA_TYPE + 4;


const POINTER_CONST: u32 = FIRST_EXTRA_TYPE + 5;


const INT_BITS_WORD: u32 = 32;


const BIT_OFFSET_SHIFT: u32 = 16;


const ONE_BYTE: u32 = 1;


const EIGHT_BITS_WORD: u32 = 8;


const UNKNOWN_TYPE_ID: u32 = 9999;


const MEMBERS_PER_TASK: usize = 2;


const GOOD_MEMBER_COUNT: usize = 3;


const UNEXPECTED: &str = "unexpected result";


struct Sample {
    types: Vec<u8>,
    strings: Vec<u8>,
}


struct FailingReader;


impl Read for FailingReader {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read failed"))
    }
}


fn push_word(buffer: &mut Vec<u8>, word: u32) {
    buffer.extend_from_slice(&word.to_le_bytes());
}


fn new_sample() -> Sample {
    Sample {
        types: Vec::new(),
        strings: vec![0],
    }
}


fn intern(sample: &mut Sample, name: &str) -> u32 {
    let offset = sample.strings.len() as u32;
    sample.strings.extend_from_slice(name.as_bytes());
    sample.strings.push(0);
    offset
}


fn add_type(sample: &mut Sample, name: &str, shape: (u32, u32, bool, u32), extra: &[u32]) {
    let (kind, vlen, flagged, size_or_type) = shape;
    let name_offset = if name.is_empty() { 0 } else { intern(sample, name) };
    push_word(&mut sample.types, name_offset);
    push_word(&mut sample.types, (u32::from(flagged) << FLAG_SHIFT) | (kind << KIND_SHIFT) | vlen);
    push_word(&mut sample.types, size_or_type);
    extra.iter().for_each(|word| push_word(&mut sample.types, *word));
}


fn finish(sample: &Sample) -> Vec<u8> {
    let type_len = sample.types.len() as u32;
    let mut bytes = Vec::new();
    [FIRST_WORD, HEADER_BYTES, 0, type_len, type_len, sample.strings.len() as u32]
        .iter()
        .for_each(|word| push_word(&mut bytes, *word));
    bytes.extend_from_slice(&sample.types);
    bytes.extend_from_slice(&sample.strings);
    bytes
}


fn add_filler_types(sample: &mut Sample) {
    add_type(sample, "int", (KIND_INT, 0, false, WORD as u32), &[INT_BITS_WORD]);
    add_type(sample, "", (KIND_PTR, 0, false, 1), &[]);
    add_type(sample, "", (KIND_ARRAY, 0, false, 0), &[1, 1, 1]);
    add_type(sample, "state", (KIND_ENUM, 1, false, WORD as u32), &[0, 0]);
    add_type(sample, "task_struct", (KIND_FWD, 0, false, 0), &[]);
    add_type(sample, "u", (KIND_UNION, 1, false, WORD as u32), &[0, 0, 0]);
    add_type(sample, "proto", (KIND_FUNC_PROTO, 1, false, 0), &[0, 0]);
}


fn add_task(sample: &mut Sample, flagged: bool, size: u32, members: &[(&str, u32)]) {
    let mut extra = Vec::new();
    members.iter().for_each(|(name, raw)| {
        let name_offset = intern(sample, name);
        let type_id = if *name == "real_parent" { POINTER_TYPE } else { INT_TYPE };
        extra.extend_from_slice(&[name_offset, type_id, *raw]);
    });
    add_type(sample, "task_struct", (KIND_STRUCT, members.len() as u32, flagged, size), &extra);
}


fn standard(members: &[(&str, u32)], flagged: bool) -> Vec<u8> {
    let mut sample = new_sample();
    add_filler_types(&mut sample);
    add_task(&mut sample, flagged, TASK_SIZE, members);
    finish(&sample)
}


fn typed(extra_types: &[ExtraType], members: &[(&str, u32, u32)], flagged: bool) -> Result<TaskOffsets, Unsupported> {
    let mut sample = new_sample();
    add_filler_types(&mut sample);
    extra_types
        .iter()
        .for_each(|(kind, target, extra)| add_type(&mut sample, "", (*kind, 0, false, *target), extra));
    let mut extra = Vec::new();
    members.iter().for_each(|(name, type_id, raw)| {
        let name_offset = intern(&mut sample, name);
        extra.extend_from_slice(&[name_offset, *type_id, *raw]);
    });
    add_type(
        &mut sample,
        "task_struct",
        (KIND_STRUCT, members.len() as u32, flagged, TASK_SIZE),
        &extra,
    );
    find_task_offsets(&finish(&sample))
}


fn typed_members(real_parent_type: u32, tgid_type: u32) -> [(&'static str, u32, u32); MEMBERS_PER_TASK] {
    [("real_parent", real_parent_type, REAL_PARENT_BITS), ("tgid", tgid_type, TGID_BITS)]
}


fn good_members() -> [(&'static str, u32); GOOD_MEMBER_COUNT] {
    [("pad", 0), ("real_parent", REAL_PARENT_BITS), ("tgid", TGID_BITS)]
}


fn with_members(members: &[(&str, u32)], flagged: bool) -> Result<TaskOffsets, Unsupported> {
    find_task_offsets(&standard(members, flagged))
}


fn patch_word(bytes: &mut [u8], index: usize, value: u32) -> Result<(), Box<dyn Error>> {
    let target = bytes.get_mut(index * WORD..(index + 1) * WORD).ok_or("word out of range")?;
    target.copy_from_slice(&value.to_le_bytes());
    Ok(())
}


fn temp_file(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(name)
}


fn failure(result: Result<TaskOffsets, Unsupported>) -> Result<&'static str, Box<dyn Error>> {
    Ok(result.err().ok_or(UNEXPECTED)?.0)
}


#[test]
fn reads_both_offsets_in_bytes() -> Result<(), Box<dyn Error>> {
    let expected = TaskOffsets {
        real_parent: REAL_PARENT_BYTE,
        tgid: TGID_BYTE,
    };
    assert_eq!(with_members(&good_members(), false), Ok(expected));
    Ok(())
}


#[test]
fn a_flagged_member_with_zero_bitfield_size_is_a_plain_member() -> Result<(), Box<dyn Error>> {
    let expected = TaskOffsets {
        real_parent: REAL_PARENT_BYTE,
        tgid: TGID_BYTE,
    };
    assert_eq!(with_members(&good_members(), true), Ok(expected));
    Ok(())
}


#[test]
fn reads_through_the_production_open() -> Result<(), Box<dyn Error>> {
    let path = temp_file("btf-good.bin");
    std::fs::write(&path, standard(&good_members(), false))?;
    assert_eq!(
        read_task_offsets(&path)?,
        TaskOffsets {
            real_parent: REAL_PARENT_BYTE,
            tgid: TGID_BYTE
        }
    );
    Ok(())
}


#[test]
fn a_missing_file_is_missing() -> Result<(), Box<dyn Error>> {
    assert_eq!(read_task_offsets(&temp_file("btf-absent.bin")), Err(Unsupported(REASON_MISSING)));
    Ok(())
}


#[test]
fn a_directory_and_an_unopenable_path_are_unreadable() -> Result<(), Box<dyn Error>> {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    assert_eq!(read_task_offsets(&directory), Err(Unsupported(REASON_UNREADABLE)));
    assert_eq!(read_task_offsets(&PathBuf::from("bad\0path")), Err(Unsupported(REASON_UNREADABLE)));
    Ok(())
}


#[test]
fn a_failing_reader_is_unreadable() -> Result<(), Box<dyn Error>> {
    assert_eq!(read_task_offsets_from(FailingReader), Err(Unsupported(REASON_UNREADABLE)));
    Ok(())
}


#[test]
fn an_empty_file_and_one_byte_are_truncated() -> Result<(), Box<dyn Error>> {
    assert_eq!(read_task_offsets_from(io::empty()), Err(Unsupported(REASON_TRUNCATED)));
    assert_eq!(read_task_offsets_from([1u8].as_slice()), Err(Unsupported(REASON_TRUNCATED)));
    Ok(())
}


#[test]
fn a_sparse_file_over_a_terabyte_is_refused_by_the_production_open() -> Result<(), Box<dyn Error>> {
    let path = temp_file("btf-sparse.bin");
    File::create(&path)?.set_len(SPARSE_BYTES)?;
    assert_eq!(read_task_offsets(&path), Err(Unsupported(REASON_OVERSIZED)));
    Ok(())
}


#[test]
fn a_file_of_exactly_the_limit_is_read_not_refused_as_oversized() -> Result<(), Box<dyn Error>> {
    let zeros = io::repeat(0).take(MAX_BTF_BYTES);
    assert_eq!(read_task_offsets_from(zeros), Err(Unsupported(REASON_NOT_BTF)));
    Ok(())
}


#[test]
fn every_truncated_prefix_is_refused() -> Result<(), Box<dyn Error>> {
    let bytes = standard(&good_members(), false);
    let refused = (0..bytes.len()).all(|length| bytes.get(..length).is_some_and(|prefix| find_task_offsets(prefix).is_err()));
    assert!(refused);
    Ok(())
}


#[test]
fn every_flipped_byte_is_handled_without_a_panic() -> Result<(), Box<dyn Error>> {
    let bytes = standard(&good_members(), false);
    let outcomes = (0..bytes.len())
        .map(|position| {
            let mut forged = bytes.clone();
            if let Some(byte) = forged.get_mut(position) {
                *byte = !*byte;
            }
            find_task_offsets(&forged).is_ok()
        })
        .count();
    assert_eq!(outcomes, bytes.len());
    Ok(())
}


#[test]
fn a_wrong_magic_or_short_header_is_not_btf() -> Result<(), Box<dyn Error>> {
    let mut wrong_magic = standard(&good_members(), false);
    patch_word(&mut wrong_magic, 0, 0)?;
    let mut short_header = standard(&good_members(), false);
    patch_word(&mut short_header, HEADER_LEN_WORD, SHORT_HEADER)?;
    assert_eq!(find_task_offsets(&wrong_magic), Err(Unsupported(REASON_NOT_BTF)));
    assert_eq!(find_task_offsets(&short_header), Err(Unsupported(REASON_NOT_BTF)));
    Ok(())
}


#[test]
fn forged_section_bounds_are_truncated() -> Result<(), Box<dyn Error>> {
    let forgeries = [
        (HEADER_LEN_WORD, u32::MAX),
        (TYPE_LEN_WORD, u32::MAX),
        (STR_OFF_WORD, u32::MAX),
        (STR_LEN_WORD, u32::MAX),
    ];
    forgeries.iter().try_for_each(|(word, value)| {
        let mut bytes = standard(&good_members(), false);
        patch_word(&mut bytes, *word, *value)?;
        assert_eq!(find_task_offsets(&bytes), Err(Unsupported(REASON_TRUNCATED)));
        Ok(())
    })
}


#[test]
fn a_real_parent_offset_beyond_the_struct_is_refused() -> Result<(), Box<dyn Error>> {
    let beyond = [("real_parent", TASK_SIZE * BITS), ("tgid", TGID_BITS)];
    let tail = [("real_parent", (TASK_SIZE - REAL_PARENT_FIELD + 1) * BITS), ("tgid", TGID_BITS)];
    let forged = [("real_parent", u32::MAX), ("tgid", TGID_BITS)];
    assert_eq!(failure(with_members(&beyond, false))?, REASON_OUT_OF_STRUCT);
    assert_eq!(failure(with_members(&tail, false))?, REASON_OUT_OF_STRUCT);
    assert_eq!(failure(with_members(&forged, false))?, REASON_BITFIELD);
    Ok(())
}


#[test]
fn an_offset_that_ends_exactly_at_the_struct_size_is_accepted() -> Result<(), Box<dyn Error>> {
    let last = [("real_parent", (TASK_SIZE - REAL_PARENT_FIELD) * BITS), ("tgid", TGID_BITS)];
    let expected = TaskOffsets {
        real_parent: TASK_SIZE - REAL_PARENT_FIELD,
        tgid: TGID_BYTE,
    };
    assert_eq!(with_members(&last, false), Ok(expected));
    Ok(())
}


#[test]
fn a_bitfield_or_unaligned_member_is_refused() -> Result<(), Box<dyn Error>> {
    let bitfield = [
        ("real_parent", REAL_PARENT_BITS),
        ("tgid", (THREE_BITS << BITFIELD_SIZE_SHIFT) | TGID_BITS),
    ];
    let unaligned = [("real_parent", REAL_PARENT_BITS), ("tgid", TGID_BITS + THREE_BITS)];
    assert_eq!(failure(with_members(&bitfield, true))?, REASON_BITFIELD);
    assert_eq!(failure(with_members(&unaligned, false))?, REASON_BITFIELD);
    Ok(())
}


#[test]
fn a_missing_member_is_named() -> Result<(), Box<dyn Error>> {
    assert_eq!(failure(with_members(&[("tgid", TGID_BITS)], false))?, REASON_NO_REAL_PARENT);
    assert_eq!(failure(with_members(&[("real_parent", REAL_PARENT_BITS)], false))?, REASON_NO_TGID);
    Ok(())
}


#[test]
fn a_struct_without_the_task_name_or_a_forward_declaration_is_not_task_struct() -> Result<(), Box<dyn Error>> {
    let mut sample = new_sample();
    add_filler_types(&mut sample);
    add_type(&mut sample, "other_struct", (KIND_STRUCT, 0, false, TASK_SIZE), &[]);
    assert_eq!(failure(find_task_offsets(&finish(&sample)))?, REASON_NO_TASK_STRUCT);
    Ok(())
}


#[test]
fn an_unknown_type_kind_is_refused_by_name() -> Result<(), Box<dyn Error>> {
    let mut sample = new_sample();
    add_type(&mut sample, "x", (KIND_UNKNOWN, 0, false, 0), &[]);
    assert_eq!(failure(find_task_offsets(&finish(&sample)))?, REASON_UNKNOWN_KIND);
    Ok(())
}


#[test]
fn the_type_cap_is_a_named_refusal() -> Result<(), Box<dyn Error>> {
    let mut sample = new_sample();
    (0..=MAX_BTF_TYPES).for_each(|_| add_type(&mut sample, "", (KIND_PTR, 0, false, 1), &[]));
    assert_eq!(failure(find_task_offsets(&finish(&sample)))?, REASON_TOO_MANY_TYPES);
    Ok(())
}


#[test]
fn a_forged_member_count_is_truncated() -> Result<(), Box<dyn Error>> {
    let mut sample = new_sample();
    add_type(&mut sample, "task_struct", (KIND_STRUCT, FORGED_VLEN, false, TASK_SIZE), &[0, 0, 0]);
    assert_eq!(failure(find_task_offsets(&finish(&sample)))?, REASON_TRUNCATED);
    Ok(())
}


#[test]
fn a_member_name_beyond_the_string_section_is_a_missing_member() -> Result<(), Box<dyn Error>> {
    let mut sample = new_sample();
    add_type(
        &mut sample,
        "task_struct",
        (KIND_STRUCT, 1, false, TASK_SIZE),
        &[FORGED_NAME_OFFSET, 1, 0],
    );
    assert_eq!(failure(find_task_offsets(&finish(&sample)))?, REASON_NO_REAL_PARENT);
    Ok(())
}


#[test]
fn the_reason_texts_hold_no_file_bytes() -> Result<(), Box<dyn Error>> {
    assert_eq!(Unsupported(REASON_MISSING).to_string(), "task offsets unsupported: BTF file is missing");
    Ok(())
}


#[test]
fn a_three_bit_int_tgid_is_refused_with_either_bitfield_encoding() -> Result<(), Box<dyn Error>> {
    let three_bit_int: &[ExtraType] = &[(KIND_INT, WORD as u32, &[THREE_BITS])];
    let unflagged = typed(three_bit_int, &typed_members(POINTER_TYPE, FIRST_EXTRA_TYPE), false);
    let flagged = typed(
        &[],
        &[
            ("real_parent", POINTER_TYPE, REAL_PARENT_BITS),
            ("tgid", INT_TYPE, (THREE_BITS << BITFIELD_SIZE_SHIFT) | TGID_BITS),
        ],
        true,
    );
    assert_eq!(failure(unflagged)?, REASON_BITFIELD);
    assert_eq!(failure(flagged)?, REASON_BITFIELD);
    Ok(())
}


#[test]
fn an_int_with_a_bit_offset_is_refused() -> Result<(), Box<dyn Error>> {
    let shifted: &[ExtraType] = &[(KIND_INT, WORD as u32, &[(1 << BIT_OFFSET_SHIFT) | INT_BITS_WORD])];
    assert_eq!(
        failure(typed(shifted, &typed_members(POINTER_TYPE, FIRST_EXTRA_TYPE), false))?,
        REASON_BITFIELD
    );
    Ok(())
}


#[test]
fn a_one_byte_real_parent_is_refused() -> Result<(), Box<dyn Error>> {
    let one_byte: &[ExtraType] = &[(KIND_INT, ONE_BYTE, &[EIGHT_BITS_WORD])];
    assert_eq!(
        failure(typed(one_byte, &typed_members(FIRST_EXTRA_TYPE, INT_TYPE), false))?,
        REASON_MEMBER_TYPE
    );
    Ok(())
}


#[test]
fn a_one_byte_tgid_and_an_eight_byte_int_tgid_are_refused() -> Result<(), Box<dyn Error>> {
    let one_byte: &[ExtraType] = &[(KIND_INT, ONE_BYTE, &[EIGHT_BITS_WORD])];
    let eight_byte: &[ExtraType] = &[(KIND_INT, REAL_PARENT_FIELD, &[REAL_PARENT_FIELD * BITS])];
    assert_eq!(
        failure(typed(one_byte, &typed_members(POINTER_TYPE, FIRST_EXTRA_TYPE), false))?,
        REASON_MEMBER_TYPE
    );
    assert_eq!(
        failure(typed(eight_byte, &typed_members(POINTER_TYPE, FIRST_EXTRA_TYPE), false))?,
        REASON_MEMBER_TYPE
    );
    Ok(())
}


#[test]
fn a_pointer_tgid_and_an_int_real_parent_are_refused() -> Result<(), Box<dyn Error>> {
    assert_eq!(
        failure(typed(&[], &typed_members(POINTER_TYPE, POINTER_TYPE), false))?,
        REASON_MEMBER_TYPE
    );
    assert_eq!(failure(typed(&[], &typed_members(INT_TYPE, INT_TYPE), false))?, REASON_MEMBER_TYPE);
    Ok(())
}


#[test]
fn an_array_or_unknown_or_void_member_type_is_refused() -> Result<(), Box<dyn Error>> {
    assert_eq!(failure(typed(&[], &typed_members(POINTER_TYPE, ARRAY_TYPE), false))?, REASON_MEMBER_TYPE);
    assert_eq!(
        failure(typed(&[], &typed_members(POINTER_TYPE, UNKNOWN_TYPE_ID), false))?,
        REASON_MEMBER_TYPE
    );
    assert_eq!(failure(typed(&[], &typed_members(POINTER_TYPE, 0), false))?, REASON_MEMBER_TYPE);
    Ok(())
}


#[test]
fn a_typedef_chain_through_every_qualifier_resolves_to_the_right_types() -> Result<(), Box<dyn Error>> {
    let chain: &[ExtraType] = &[
        (KIND_TYPEDEF, INT_TYPE, &[]),
        (KIND_CONST, FIRST_EXTRA_TYPE, &[]),
        (KIND_VOLATILE, CONST_TYPE, &[]),
        (KIND_RESTRICT, VOLATILE_TYPE, &[]),
        (KIND_TYPEDEF, POINTER_TYPE, &[]),
        (KIND_CONST, POINTER_TYPEDEF, &[]),
    ];
    let expected = TaskOffsets {
        real_parent: REAL_PARENT_BYTE,
        tgid: TGID_BYTE,
    };
    assert_eq!(typed(chain, &typed_members(POINTER_CONST, RESTRICT_TYPE), false), Ok(expected));
    Ok(())
}


#[test]
fn a_typedef_to_the_wrong_type_is_refused() -> Result<(), Box<dyn Error>> {
    let chain: &[ExtraType] = &[(KIND_TYPEDEF, POINTER_TYPE, &[])];
    assert_eq!(
        failure(typed(chain, &typed_members(POINTER_TYPE, FIRST_EXTRA_TYPE), false))?,
        REASON_MEMBER_TYPE
    );
    Ok(())
}


#[test]
fn a_typedef_cycle_and_a_self_loop_are_named() -> Result<(), Box<dyn Error>> {
    let cycle: &[ExtraType] = &[(KIND_TYPEDEF, FIRST_EXTRA_TYPE + 1, &[]), (KIND_CONST, FIRST_EXTRA_TYPE, &[])];
    let own_loop: &[ExtraType] = &[(KIND_TYPEDEF, FIRST_EXTRA_TYPE, &[])];
    assert_eq!(
        failure(typed(cycle, &typed_members(POINTER_TYPE, FIRST_EXTRA_TYPE), false))?,
        REASON_TYPE_CHAIN
    );
    assert_eq!(
        failure(typed(own_loop, &typed_members(FIRST_EXTRA_TYPE, INT_TYPE), false))?,
        REASON_TYPE_CHAIN
    );
    Ok(())
}


fn typedef_chain(modifiers: u32) -> Vec<ExtraType<'static>> {
    (0..modifiers)
        .map(|i| {
            (
                KIND_TYPEDEF,
                if i + 1 == modifiers { INT_TYPE } else { FIRST_EXTRA_TYPE + i + 1 },
                &[] as &[u32],
            )
        })
        .collect()
}


#[test]
fn a_chain_at_the_cap_is_refused_and_one_shorter_is_accepted() -> Result<(), Box<dyn Error>> {
    let members = typed_members(POINTER_TYPE, FIRST_EXTRA_TYPE);
    let refused = typed(&typedef_chain(MAX_TYPE_CHAIN), &members, false);
    let accepted = typed(&typedef_chain(MAX_TYPE_CHAIN - 1), &members, false);
    assert_eq!(failure(refused)?, REASON_TYPE_CHAIN);
    assert!(accepted.is_ok());
    Ok(())
}


#[test]
fn a_cut_type_names_truncation_not_a_missing_struct() -> Result<(), Box<dyn Error>> {
    let mut sample = new_sample();
    add_type(&mut sample, "other", (KIND_UNION, FORGED_VLEN, false, WORD as u32), &[0, 0, 0]);
    assert_eq!(failure(find_task_offsets(&finish(&sample)))?, REASON_TRUNCATED);
    Ok(())
}


fn valid_sample() -> Sample {
    let mut sample = new_sample();
    add_filler_types(&mut sample);
    add_task(&mut sample, false, TASK_SIZE, &good_members());
    sample
}


#[test]
fn a_valid_task_struct_followed_by_a_cut_type_is_truncated() -> Result<(), Box<dyn Error>> {
    let mut sample = valid_sample();
    add_type(&mut sample, "other", (KIND_UNION, FORGED_VLEN, false, WORD as u32), &[0, 0, 0]);
    assert_eq!(failure(find_task_offsets(&finish(&sample)))?, REASON_TRUNCATED);
    Ok(())
}


#[test]
fn a_valid_task_struct_followed_by_types_past_the_cap_is_refused() -> Result<(), Box<dyn Error>> {
    let mut sample = valid_sample();
    (0..=MAX_BTF_TYPES).for_each(|_| add_type(&mut sample, "", (KIND_PTR, 0, false, 1), &[]));
    assert_eq!(failure(find_task_offsets(&finish(&sample)))?, REASON_TOO_MANY_TYPES);
    Ok(())
}
