use crate::types::TestResult;
use std::error::Error;
use sys_windows::types::VersionParts;


pub const PE_OFFSET: usize = 0x80;


pub const RAW_POINTER: usize = 0x400;


pub const SECTION_RVA: usize = 0x1000;


pub const ROOT_DIRECTORY: usize = RAW_POINTER;


pub const TYPE_DIRECTORY: usize = 0x20;


pub const NAME_DIRECTORY: usize = 0x40;


pub const DATA_ENTRY: usize = 0x60;


pub const DATA_START: usize = 0x80;


pub const MAGIC_PE32: u16 = 0x10B;


pub const MAGIC_PE32_PLUS: u16 = 0x20B;


pub const SUBDIRECTORY_FLAG: u32 = 0x8000_0000;


const E_LFANEW: usize = 0x3C;


const COFF_SECTIONS: usize = 6;


const COFF_OPTIONAL_SIZE: usize = 20;


const OPTIONAL_START: usize = 24;


const PE32_DIRECTORIES_AT: usize = 92;


const PE32_PLUS_DIRECTORIES_AT: usize = 108;


const DIRECTORY_COUNT: u32 = 16;


const DIRECTORY_ENTRY: usize = 8;


const RESOURCE_INDEX: usize = 2;


const RT_VERSION: u32 = 16;


const LANGUAGE: u32 = 0x409;


const FIXED_SIGNATURE: u32 = 0xFEEF_04BD;


const FIXED_BYTES: usize = 52;


const STRUCT_VERSION: u32 = 0x1_0000;


const WORD: usize = 4;


const BLOCK_HEADER: usize = 6;


const IDS_AT: usize = 14;


const ENTRY_NAME_AT: usize = 16;


const ENTRY_OFFSET_AT: usize = 20;


const SECTION_RVA_AT: usize = 12;


const SECTION_SIZE_AT: usize = 16;


const SECTION_POINTER_AT: usize = 20;


const HALF: u32 = 16;


const FILE_PADDING: usize = 0x2000;


const STRING_KIND: u16 = 1;


pub const DEFAULT_VERSION: VersionParts = [15, 22, 0, 0];


pub struct VersionSpec {
    pub strings: Vec<(String, String)>,
    pub version: VersionParts,
    pub magic: u16,
}


pub fn spec_with(strings: &[(&str, &str)]) -> VersionSpec {
    VersionSpec {
        strings: strings.iter().map(|(key, value)| (key.to_string(), value.to_string())).collect(),
        version: DEFAULT_VERSION,
        magic: MAGIC_PE32_PLUS,
    }
}


pub fn sysmon_spec() -> VersionSpec {
    spec_with(&[
        ("CompanyName", "Sysinternals - www.sysinternals.com"),
        ("FileDescription", "System activity monitor"),
        ("FileVersion", "15.22"),
        ("InternalName", "System Monitor"),
        ("OriginalFilename", "Sysmon64.exe"),
        ("ProductName", "Sysinternals Sysmon"),
    ])
}


fn units(text: &str) -> Vec<u8> {
    text.encode_utf16().chain(std::iter::once(0)).flat_map(u16::to_le_bytes).collect()
}


fn pad_word(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.len().next_multiple_of(WORD), 0);
}


pub fn block(key: &str, kind: u16, value: &[u8], value_units: u16, children: &[Vec<u8>]) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![0u8; BLOCK_HEADER];
    bytes.extend(units(key));
    pad_word(&mut bytes);
    bytes.extend(value);
    pad_word(&mut bytes);
    children.iter().for_each(|child| {
        bytes.extend(child);
        pad_word(&mut bytes);
    });
    let length = u16::try_from(bytes.len())?;
    bytes.splice(
        0..BLOCK_HEADER,
        [length.to_le_bytes(), value_units.to_le_bytes(), kind.to_le_bytes()].concat(),
    );
    Ok(bytes)
}


fn fixed_info(version: VersionParts) -> Vec<u8> {
    let [major, minor, build, revision] = version;
    let most = (u32::from(major) << HALF) | u32::from(minor);
    let least = (u32::from(build) << HALF) | u32::from(revision);
    let mut bytes = [FIXED_SIGNATURE, STRUCT_VERSION, most, least]
        .iter()
        .flat_map(|word| word.to_le_bytes())
        .collect::<Vec<u8>>();
    bytes.resize(FIXED_BYTES, 0);
    bytes
}


pub fn version_blob(spec: &VersionSpec) -> Result<Vec<u8>, Box<dyn Error>> {
    let strings = spec
        .strings
        .iter()
        .map(|(key, value)| block(key, STRING_KIND, &units(value), u16::try_from(value.encode_utf16().count() + 1)?, &[]))
        .collect::<Result<Vec<_>, _>>()?;
    let table = block("040904b0", STRING_KIND, &[], 0, &strings)?;
    let info = block("StringFileInfo", STRING_KIND, &[], 0, &[table])?;
    block("VS_VERSION_INFO", 0, &fixed_info(spec.version), u16::try_from(FIXED_BYTES)?, &[info])
}


pub fn poke(bytes: &mut [u8], offset: usize, value: &[u8]) -> TestResult {
    bytes
        .get_mut(offset..offset + value.len())
        .ok_or("poke outside the file")?
        .copy_from_slice(value);
    Ok(())
}


pub fn poke_u32(bytes: &mut [u8], offset: usize, value: u32) -> TestResult {
    poke(bytes, offset, &value.to_le_bytes())
}


pub fn poke_u16(bytes: &mut [u8], offset: usize, value: u16) -> TestResult {
    poke(bytes, offset, &value.to_le_bytes())
}


pub fn optional_size(magic: u16) -> usize {
    let directories_at = if magic == MAGIC_PE32 {
        PE32_DIRECTORIES_AT
    } else {
        PE32_PLUS_DIRECTORIES_AT
    };
    directories_at + WORD + DIRECTORY_ENTRY * usize::try_from(DIRECTORY_COUNT).unwrap_or(0)
}


pub fn directories_count_offset(magic: u16) -> usize {
    PE_OFFSET
        + OPTIONAL_START
        + if magic == MAGIC_PE32 {
            PE32_DIRECTORIES_AT
        } else {
            PE32_PLUS_DIRECTORIES_AT
        }
}


pub fn section_table(magic: u16) -> usize {
    PE_OFFSET + OPTIONAL_START + optional_size(magic)
}


pub fn pe_file(spec: &VersionSpec) -> Result<Vec<u8>, Box<dyn Error>> {
    pe_with_blob(&version_blob(spec)?, spec.magic)
}


pub fn pe_with_blob(blob: &[u8], magic: u16) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut bytes = vec![0u8; RAW_POINTER + DATA_START + blob.len() + FILE_PADDING];
    poke_u32(&mut bytes, E_LFANEW, u32::try_from(PE_OFFSET)?)?;
    poke_u16(&mut bytes, PE_OFFSET + COFF_SECTIONS, 1)?;
    poke_u16(&mut bytes, PE_OFFSET + COFF_OPTIONAL_SIZE, u16::try_from(optional_size(magic))?)?;
    poke_u16(&mut bytes, PE_OFFSET + OPTIONAL_START, magic)?;
    let count_at = directories_count_offset(magic);
    poke_u32(&mut bytes, count_at, DIRECTORY_COUNT)?;
    poke_u32(
        &mut bytes,
        count_at + WORD + RESOURCE_INDEX * DIRECTORY_ENTRY,
        u32::try_from(SECTION_RVA)?,
    )?;
    let header = section_table(magic);
    poke_u32(&mut bytes, header + SECTION_RVA_AT, u32::try_from(SECTION_RVA)?)?;
    poke_u32(
        &mut bytes,
        header + SECTION_SIZE_AT,
        u32::try_from(DATA_START + blob.len() + FILE_PADDING)?,
    )?;
    poke_u32(&mut bytes, header + SECTION_POINTER_AT, u32::try_from(RAW_POINTER)?)?;
    poke_u16(&mut bytes, ROOT_DIRECTORY + IDS_AT, 1)?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + ENTRY_NAME_AT, RT_VERSION)?;
    poke_u32(
        &mut bytes,
        ROOT_DIRECTORY + ENTRY_OFFSET_AT,
        SUBDIRECTORY_FLAG | u32::try_from(TYPE_DIRECTORY)?,
    )?;
    poke_u16(&mut bytes, ROOT_DIRECTORY + TYPE_DIRECTORY + IDS_AT, 1)?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + TYPE_DIRECTORY + ENTRY_NAME_AT, 1)?;
    poke_u32(
        &mut bytes,
        ROOT_DIRECTORY + TYPE_DIRECTORY + ENTRY_OFFSET_AT,
        SUBDIRECTORY_FLAG | u32::try_from(NAME_DIRECTORY)?,
    )?;
    poke_u16(&mut bytes, ROOT_DIRECTORY + NAME_DIRECTORY + IDS_AT, 1)?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + NAME_DIRECTORY + ENTRY_NAME_AT, LANGUAGE)?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + NAME_DIRECTORY + ENTRY_OFFSET_AT, u32::try_from(DATA_ENTRY)?)?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + DATA_ENTRY, u32::try_from(SECTION_RVA + DATA_START)?)?;
    poke_u32(&mut bytes, ROOT_DIRECTORY + DATA_ENTRY + WORD, u32::try_from(blob.len())?)?;
    poke(&mut bytes, RAW_POINTER + DATA_START, blob)?;
    Ok(bytes)
}
