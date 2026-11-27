use crate::pe::{
    block, directories_count_offset, pe_file, pe_with_blob, poke, poke_u16, poke_u32, section_table, spec_with, sysmon_spec, version_blob,
    DATA_ENTRY, DATA_START, DEFAULT_VERSION, MAGIC_PE32, MAGIC_PE32_PLUS, NAME_DIRECTORY, PE_OFFSET, RAW_POINTER, ROOT_DIRECTORY, SUBDIRECTORY_FLAG,
    TYPE_DIRECTORY,
};
use crate::types::TestResult;
use sys_windows::pe_version::{parse_version, MAX_FILE_BYTES};
use sys_windows::types::{SignatureError, VersionParts};


const WORD: usize = 4;


const OPTIONAL_AT: usize = 24;


const RESOURCE_INDEX: u32 = 2;


const UNKNOWN_MAGIC: u16 = 0x107;


const E_LFANEW_AT: usize = 0x3C;


const RESOURCE_DIRECTORY_AT: usize = 2 * 8;


const SECTION_COUNT_AT: usize = 6;


const VALUE_UNITS_BACK: usize = 4;


const OTHER_VERSION: VersionParts = [1, 2, 3, 4];


const UNIT: usize = 2;


const ENTRY_NAME_AT: usize = 16;


const ENTRY_OFFSET_AT: usize = 20;


const NAMED_AT: usize = 12;


const SECOND_ENTRY: usize = 8;


const BIG_SIZE: u32 = 0x2_0000;


const UNMAPPED_RVA: u32 = 0x9_0000;


const HUGE_OFFSET: u32 = 0x7FFF_0000;


const TOO_MANY_UNITS: u16 = 300;


const LOW_SURROGATE_START: u16 = 0xD800;


const MANY_STRINGS: usize = 300;


const OTHER_RESOURCE: u32 = 17;


const SMALL_LENGTH: u16 = 2;


const HUGE_LENGTH: u16 = 0xFFFF;


const LONG_KEY_UNITS: usize = 80;


const FIXED_AT_IN_BLOB: usize = 36;


const BAD_SIGNATURE: u32 = 0x1234_5678;


const VALUE_BYTES_AT: usize = 2;


const NOT_52: u16 = 40;


const MAX_BYTES_SANITY: u64 = 64 * 1024 * 1024;


fn data_offset() -> usize {
    RAW_POINTER + DATA_START
}


fn locate(bytes: &[u8], text: &str) -> Result<usize, Box<dyn std::error::Error>> {
    let needle = text.encode_utf16().flat_map(u16::to_le_bytes).collect::<Vec<u8>>();
    Ok(bytes
        .windows(needle.len())
        .position(|window| window == needle.as_slice())
        .ok_or("text not in the file")?)
}


fn refused(bytes: &[u8]) -> bool {
    matches!(parse_version(bytes), Err(SignatureError::NoVersionInfo))
}


#[test]
fn the_sysmon_resource_is_read_from_a_pe32_plus_file() -> TestResult {
    let info = parse_version(&pe_file(&sysmon_spec())?)?;
    assert_eq!(info.original_file_name.as_deref(), Some("Sysmon64.exe"));
    assert_eq!(info.internal_name.as_deref(), Some("System Monitor"));
    assert_eq!(info.product_name.as_deref(), Some("Sysinternals Sysmon"));
    assert_eq!(info.file_description.as_deref(), Some("System activity monitor"));
    assert_eq!(info.company_name.as_deref(), Some("Sysinternals - www.sysinternals.com"));
    assert_eq!(info.file_version_text.as_deref(), Some("15.22"));
    assert_eq!(info.file_version, DEFAULT_VERSION);
    Ok(())
}


#[test]
fn a_pe32_file_is_read_too() -> TestResult {
    let mut spec = sysmon_spec();
    spec.magic = MAGIC_PE32;
    spec.version = OTHER_VERSION;
    let info = parse_version(&pe_file(&spec)?)?;
    assert_eq!(info.file_version, OTHER_VERSION);
    assert_eq!(info.product_name.as_deref(), Some("Sysinternals Sysmon"));
    Ok(())
}


#[test]
fn a_missing_original_file_name_is_none_and_never_another_field() -> TestResult {
    let info = parse_version(&pe_file(&spec_with(&[
        ("InternalName", "System Monitor"),
        ("ProductName", "Sysinternals Sysmon"),
    ]))?)?;
    assert_eq!(info.original_file_name, None);
    assert_eq!(info.internal_name.as_deref(), Some("System Monitor"));
    assert_eq!(info.company_name, None);
    assert_eq!(info.file_version_text, None);
    Ok(())
}


#[test]
fn an_empty_string_table_gives_no_names() -> TestResult {
    let info = parse_version(&pe_file(&spec_with(&[]))?)?;
    assert_eq!(info.product_name, None);
    Ok(())
}


#[test]
fn every_prefix_of_the_file_is_judged_without_panic_and_only_whole_data_is_read() -> TestResult {
    let spec = sysmon_spec();
    let bytes = pe_file(&spec)?;
    let end = data_offset() + version_blob(&spec)?.len();
    (0..=bytes.len()).try_for_each(|length| -> TestResult {
        let prefix = bytes.get(..length).ok_or("prefix")?;
        assert_eq!(parse_version(prefix).is_ok(), length >= end, "prefix of {length} bytes");
        Ok(())
    })
}


#[test]
fn an_unknown_optional_header_magic_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u16(&mut bytes, PE_OFFSET + OPTIONAL_AT, UNKNOWN_MAGIC)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_pe_offset_outside_the_file_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u32(&mut bytes, E_LFANEW_AT, HUGE_OFFSET)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn too_few_data_directories_are_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u32(&mut bytes, directories_count_offset(MAGIC_PE32_PLUS), RESOURCE_INDEX)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_resource_rva_outside_every_section_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u32(
        &mut bytes,
        directories_count_offset(MAGIC_PE32_PLUS) + WORD + RESOURCE_DIRECTORY_AT,
        UNMAPPED_RVA,
    )?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_file_with_no_section_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u16(&mut bytes, PE_OFFSET + SECTION_COUNT_AT, 0)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_section_table_cut_short_is_refused() -> TestResult {
    let bytes = pe_file(&sysmon_spec())?;
    let cut = bytes.get(..section_table(MAGIC_PE32_PLUS) + WORD).ok_or("cut")?;
    assert!(refused(cut));
    Ok(())
}


#[test]
fn a_resource_tree_without_a_version_type_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + ENTRY_NAME_AT, OTHER_RESOURCE)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_named_entry_is_never_taken_for_the_version_id() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u16(&mut bytes, ROOT_DIRECTORY + NAMED_AT, 1)?;
    poke_u16(&mut bytes, ROOT_DIRECTORY + NAMED_AT + UNIT, 1)?;
    let original = bytes
        .get(ROOT_DIRECTORY + ENTRY_NAME_AT..ROOT_DIRECTORY + ENTRY_NAME_AT + SECOND_ENTRY)
        .ok_or("entry")?
        .to_vec();
    poke(&mut bytes, ROOT_DIRECTORY + ENTRY_NAME_AT + SECOND_ENTRY, &original)?;
    assert!(parse_version(&bytes).is_ok());
    poke_u32(&mut bytes, ROOT_DIRECTORY + ENTRY_NAME_AT + SECOND_ENTRY, OTHER_RESOURCE)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn an_entry_list_longer_than_the_file_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u16(&mut bytes, ROOT_DIRECTORY + NAMED_AT + UNIT, u16::MAX)?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + ENTRY_NAME_AT, OTHER_RESOURCE)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_type_entry_that_is_not_a_subdirectory_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + ENTRY_OFFSET_AT, u32::try_from(TYPE_DIRECTORY)?)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_leaf_that_is_a_subdirectory_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u32(
        &mut bytes,
        ROOT_DIRECTORY + NAME_DIRECTORY + ENTRY_OFFSET_AT,
        SUBDIRECTORY_FLAG | u32::try_from(DATA_ENTRY)?,
    )?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_data_entry_pointing_outside_every_section_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + DATA_ENTRY, UNMAPPED_RVA)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_version_resource_larger_than_its_bound_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + DATA_ENTRY + WORD, BIG_SIZE)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_version_resource_running_past_the_file_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    let total = u32::try_from(bytes.len())?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + DATA_ENTRY + WORD, total)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_root_block_with_the_wrong_key_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    let at = locate(&bytes, "VS_VERSION_INFO")?;
    poke_u16(&mut bytes, at, u16::from(b'X'))?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_root_value_of_another_size_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u16(&mut bytes, data_offset() + VALUE_BYTES_AT, NOT_52)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_fixed_info_without_its_signature_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u32(&mut bytes, data_offset() + FIXED_AT_IN_BLOB, BAD_SIGNATURE)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_block_shorter_than_its_header_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u16(&mut bytes, data_offset(), SMALL_LENGTH)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_block_longer_than_the_data_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    poke_u16(&mut bytes, data_offset(), HUGE_LENGTH)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_key_that_never_ends_is_refused() -> TestResult {
    let long_key = "K".repeat(LONG_KEY_UNITS);
    let blob = block(&long_key, 0, &[], 0, &[])?;
    assert!(refused(&pe_with_blob(&blob, MAGIC_PE32_PLUS)?));
    Ok(())
}


#[test]
fn a_key_running_past_its_block_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    let at = locate(&bytes, "VS_VERSION_INFO")?;
    poke_u16(&mut bytes, data_offset(), u16::try_from(at - data_offset() + UNIT)?)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_string_file_info_key_that_is_not_utf16_is_not_found() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    let at = locate(&bytes, "StringFileInfo")?;
    poke_u16(&mut bytes, at, LOW_SURROGATE_START)?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_file_without_a_string_file_info_is_refused() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    let at = locate(&bytes, "StringFileInfo")?;
    poke_u16(&mut bytes, at, u16::from(b'X'))?;
    assert!(refused(&bytes));
    Ok(())
}


#[test]
fn a_string_longer_than_its_bound_is_none() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    let at = locate(&bytes, "ProductName")?;
    poke_u16(&mut bytes, at - VALUE_UNITS_BACK, TOO_MANY_UNITS)?;
    let info = parse_version(&bytes)?;
    assert_eq!(info.product_name, None);
    assert_eq!(info.internal_name.as_deref(), Some("System Monitor"));
    Ok(())
}


#[test]
fn a_string_that_is_not_utf16_is_none() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    let at = locate(&bytes, "Sysinternals Sysmon")?;
    poke_u16(&mut bytes, at, LOW_SURROGATE_START)?;
    assert_eq!(parse_version(&bytes)?.product_name, None);
    Ok(())
}


#[test]
fn a_string_running_past_the_data_is_none() -> TestResult {
    let mut bytes = pe_file(&sysmon_spec())?;
    let at = locate(&bytes, "ProductName")?;
    poke_u16(&mut bytes, at - VALUE_UNITS_BACK, u16::MAX)?;
    assert_eq!(parse_version(&bytes)?.product_name, None);
    Ok(())
}


#[test]
fn only_the_first_blocks_of_a_table_are_read() -> TestResult {
    let names = (0..MANY_STRINGS)
        .map(|index| (format!("K{index:04}"), "v".to_string()))
        .collect::<Vec<_>>();
    let mut spec = spec_with(&[]);
    spec.strings = names;
    spec.strings.push(("ProductName".to_string(), "late".to_string()));
    assert_eq!(parse_version(&pe_file(&spec)?)?.product_name, None);
    let mut early = spec_with(&[("ProductName", "early")]);
    early
        .strings
        .extend((0..MANY_STRINGS).map(|index| (format!("K{index:04}"), "v".to_string())));
    assert_eq!(parse_version(&pe_file(&early)?)?.product_name.as_deref(), Some("early"));
    Ok(())
}


#[test]
fn the_file_bound_is_sixty_four_mebibytes() -> TestResult {
    assert_eq!(MAX_FILE_BYTES, MAX_BYTES_SANITY);
    Ok(())
}
