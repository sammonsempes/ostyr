use crate::common::types::TestResult;
use crate::support::{elf_with_types, le, PT_INTERP, PT_LOAD, QUAD, SHORT};
use connector_manifest::elf::{check_static_elf, read_le, CLASS_OFFSET, COUNT_FIELD, DATA_OFFSET, ENTRY_SIZE_FIELD, PROGRAM_OFFSET_FIELD};
use connector_manifest::error::ConnectorError;


const SHORT_HEADER: usize = 6;


const TRUNCATED_AT: usize = 66;


const WRONG_CLASS: u8 = 1;


const WRONG_DATA: u8 = 2;


const TINY_ENTRY_SIZE: u64 = 8;


const FAR_TABLE: u64 = 0x00ff_ffff_ffff;


const HUGE_COUNT: u64 = 60_000;


const SAMPLE_FIELD: [u8; 4] = [1, 2, 0, 0];


const WORD_AT_ZERO: u64 = 0x0201;


const WORD_AT_ONE: u64 = 2;


const LAST_OFFSET: u64 = 3;


fn reason(bytes: &[u8]) -> Result<&'static str, Box<dyn std::error::Error>> {
    match check_static_elf(bytes) {
        Err(ConnectorError::UnsupportedEntry { reason }) => Ok(reason),
        other => Err(format!("expected UnsupportedEntry, got {other:?}").into()),
    }
}


fn patched(mut bytes: Vec<u8>, offset: usize, value: &[u8]) -> Vec<u8> {
    bytes.splice(offset..offset + value.len(), value.iter().copied());
    bytes
}


#[test]
fn a_static_elf_without_an_interpreter_is_accepted() -> TestResult {
    check_static_elf(&elf_with_types(&[PT_LOAD, PT_LOAD]))?;
    check_static_elf(&elf_with_types(&[]))?;
    Ok(())
}


#[test]
fn a_program_header_naming_an_interpreter_is_refused_wherever_it_stands() -> TestResult {
    assert!(reason(&elf_with_types(&[PT_INTERP]))?.contains("PT_INTERP"));
    assert!(reason(&elf_with_types(&[PT_LOAD, PT_INTERP, PT_LOAD]))?.contains("PT_INTERP"));
    assert!(reason(&elf_with_types(&[PT_LOAD, PT_LOAD, PT_INTERP]))?.contains("PT_INTERP"));
    Ok(())
}


#[test]
fn a_script_or_a_foreign_elf_is_refused() -> TestResult {
    assert!(reason(b"#!/tmp/x\nexit 0\n")?.contains("not an ELF"));
    assert!(reason(b"")?.contains("not an ELF"));
    let valid = elf_with_types(&[PT_LOAD]);
    assert!(reason(&patched(valid.clone(), CLASS_OFFSET, &[WRONG_CLASS]))?.contains("64-bit"));
    assert!(reason(&patched(valid, DATA_OFFSET, &[WRONG_DATA]))?.contains("little-endian"));
    Ok(())
}


#[test]
fn a_truncated_header_or_table_is_refused() -> TestResult {
    let valid = elf_with_types(&[PT_LOAD]);
    let short = valid.get(..SHORT_HEADER).ok_or("short")?;
    assert!(reason(short)?.contains("header is truncated"));
    let cut = valid.get(..TRUNCATED_AT).ok_or("cut")?;
    assert!(reason(cut)?.contains("program headers are truncated"));
    let far = patched(valid.clone(), PROGRAM_OFFSET_FIELD, &le(FAR_TABLE, QUAD));
    assert!(reason(&far)?.contains("program headers are truncated"));
    let huge = patched(valid, COUNT_FIELD, &le(HUGE_COUNT, SHORT));
    assert!(reason(&huge)?.contains("program headers are truncated"));
    Ok(())
}


#[test]
fn a_wrong_program_header_size_is_refused() -> TestResult {
    let valid = elf_with_types(&[PT_LOAD]);
    let tiny = patched(valid, ENTRY_SIZE_FIELD, &le(TINY_ENTRY_SIZE, SHORT));
    assert!(reason(&tiny)?.contains("size is wrong"));
    Ok(())
}


#[test]
fn little_endian_fields_read_whole_or_not_at_all() -> TestResult {
    let bytes = SAMPLE_FIELD;
    assert_eq!(read_le(&bytes, 0, SHORT), Some(WORD_AT_ZERO));
    assert_eq!(read_le(&bytes, 1, SHORT), Some(WORD_AT_ONE));
    assert_eq!(read_le(&bytes, LAST_OFFSET, SHORT), None);
    assert_eq!(read_le(&bytes, u64::MAX, SHORT), None);
    Ok(())
}
