use crate::types::{SignatureError, VersionInfo, VersionParts};


const E_LFANEW_OFFSET: usize = 0x3C;


const SECTION_COUNT_OFFSET: usize = 6;


const OPTIONAL_SIZE_OFFSET: usize = 20;


const OPTIONAL_HEADER_OFFSET: usize = 24;


const MAGIC_PE32: u16 = 0x10B;


const MAGIC_PE32_PLUS: u16 = 0x20B;


const DIRECTORY_COUNT_OFFSET_PE32: usize = 92;


const DIRECTORY_COUNT_OFFSET_PE32_PLUS: usize = 108;


const DIRECTORY_ENTRY_BYTES: usize = 8;


const RESOURCE_DIRECTORY_INDEX: usize = 2;


const SECTION_HEADER_BYTES: usize = 40;


const MAX_SECTIONS: usize = 96;


const SECTION_VIRTUAL_ADDRESS: usize = 12;


const SECTION_RAW_SIZE: usize = 16;


const SECTION_RAW_POINTER: usize = 20;


const RESOURCE_HEADER_BYTES: usize = 16;


const RESOURCE_NAMED_COUNT: usize = 12;


const RESOURCE_ID_COUNT: usize = 14;


const RESOURCE_ENTRY_BYTES: usize = 8;


const RT_VERSION: u32 = 16;


const SUBDIRECTORY_FLAG: u32 = 0x8000_0000;


const MAX_VERSION_BYTES: usize = 0x1_0000;


const BLOCK_HEADER_BYTES: usize = 6;


const MAX_KEY_UNITS: usize = 64;


const MAX_STRING_UNITS: usize = 256;


const MAX_BLOCKS: usize = 256;


const WORD_BYTES: usize = 4;


const UNIT_BYTES: usize = 2;


const ROOT_KEY: &str = "VS_VERSION_INFO";


const FIXED_INFO_BYTES: u16 = 52;


const FIXED_INFO_SIGNATURE: u32 = 0xFEEF_04BD;


const FIXED_VERSION_OFFSET: usize = 8;


const STRING_FILE_INFO: &str = "StringFileInfo";


const KEY_ORIGINAL_FILE_NAME: &str = "OriginalFilename";


const KEY_INTERNAL_NAME: &str = "InternalName";


const KEY_PRODUCT_NAME: &str = "ProductName";


const KEY_FILE_DESCRIPTION: &str = "FileDescription";


const KEY_COMPANY_NAME: &str = "CompanyName";


const KEY_FILE_VERSION: &str = "FileVersion";


/// The largest file the version and digest steps read, in bytes.
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;


struct Block {
    end: usize,
    key: String,
    value_offset: usize,
    value_units: usize,
}


fn bytes_at<const LENGTH: usize>(bytes: &[u8], offset: usize) -> Option<[u8; LENGTH]> {
    bytes.get(offset..)?.get(..LENGTH)?.try_into().ok()
}


fn u16_at(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes_at::<UNIT_BYTES>(bytes, offset).map(u16::from_le_bytes)
}


fn u32_at(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes_at::<WORD_BYTES>(bytes, offset).map(u32::from_le_bytes)
}


fn usize_at(bytes: &[u8], offset: usize) -> Option<usize> {
    u32_at(bytes, offset).and_then(|value| usize::try_from(value).ok())
}


fn align_word(offset: usize) -> usize {
    offset.next_multiple_of(WORD_BYTES)
}


fn directory_count_offset(magic: u16) -> Option<usize> {
    match magic {
        MAGIC_PE32 => Some(DIRECTORY_COUNT_OFFSET_PE32),
        MAGIC_PE32_PLUS => Some(DIRECTORY_COUNT_OFFSET_PE32_PLUS),
        _ => None,
    }
}


fn section_offset(bytes: &[u8], table: usize, index: usize, rva: usize) -> Option<usize> {
    let base = table.checked_add(index.checked_mul(SECTION_HEADER_BYTES)?)?;
    let virtual_address = usize_at(bytes, base.checked_add(SECTION_VIRTUAL_ADDRESS)?)?;
    let raw_size = usize_at(bytes, base.checked_add(SECTION_RAW_SIZE)?)?;
    let raw_pointer = usize_at(bytes, base.checked_add(SECTION_RAW_POINTER)?)?;
    let inside = rva.checked_sub(virtual_address).filter(|delta| *delta < raw_size)?;
    raw_pointer.checked_add(inside)
}


fn rva_to_offset(bytes: &[u8], table: usize, sections: usize, rva: usize) -> Option<usize> {
    (0..sections.min(MAX_SECTIONS)).find_map(|index| section_offset(bytes, table, index, rva))
}


fn resource_entry(bytes: &[u8], directory: usize, wanted: Option<u32>) -> Option<u32> {
    let named = usize::from(u16_at(bytes, directory.checked_add(RESOURCE_NAMED_COUNT)?)?);
    let ids = usize::from(u16_at(bytes, directory.checked_add(RESOURCE_ID_COUNT)?)?);
    let first = directory.checked_add(RESOURCE_HEADER_BYTES)?;
    (0..named.checked_add(ids)?).find_map(|index| {
        let entry = first.checked_add(index.checked_mul(RESOURCE_ENTRY_BYTES)?)?;
        let name = u32_at(bytes, entry)?;
        let offset = u32_at(bytes, entry.checked_add(WORD_BYTES)?)?;
        wanted.map_or(Some(offset), |id| (index >= named && name == id).then_some(offset))
    })
}


fn subdirectory(field: u32) -> Option<usize> {
    (field & SUBDIRECTORY_FLAG != 0).then(|| usize::try_from(field & !SUBDIRECTORY_FLAG).ok())?
}


fn version_data(bytes: &[u8]) -> Option<&[u8]> {
    let pe = usize_at(bytes, E_LFANEW_OFFSET)?;
    let optional = pe.checked_add(OPTIONAL_HEADER_OFFSET)?;
    let sections = usize::from(u16_at(bytes, pe.checked_add(SECTION_COUNT_OFFSET)?)?);
    let optional_size = usize::from(u16_at(bytes, pe.checked_add(OPTIONAL_SIZE_OFFSET)?)?);
    let count_offset = optional.checked_add(directory_count_offset(u16_at(bytes, optional)?)?)?;
    let directories = usize_at(bytes, count_offset)?;
    (directories > RESOURCE_DIRECTORY_INDEX).then_some(())?;
    let entry = count_offset
        .checked_add(WORD_BYTES)?
        .checked_add(RESOURCE_DIRECTORY_INDEX.checked_mul(DIRECTORY_ENTRY_BYTES)?)?;
    let table = optional.checked_add(optional_size)?;
    let root = rva_to_offset(bytes, table, sections, usize_at(bytes, entry)?)?;
    let type_directory = root.checked_add(subdirectory(resource_entry(bytes, root, Some(RT_VERSION))?)?)?;
    let name_directory = root.checked_add(subdirectory(resource_entry(bytes, type_directory, None)?)?)?;
    let leaf_field = resource_entry(bytes, name_directory, None)?;
    (leaf_field & SUBDIRECTORY_FLAG == 0).then_some(())?;
    let data_entry = root.checked_add(usize::try_from(leaf_field).ok()?)?;
    let start = rva_to_offset(bytes, table, sections, usize_at(bytes, data_entry)?)?;
    let size = usize_at(bytes, data_entry.checked_add(WORD_BYTES)?)?;
    (size <= MAX_VERSION_BYTES).then_some(())?;
    bytes.get(start..start.checked_add(size)?)
}


fn utf16_at(data: &[u8], offset: usize, units: usize) -> Option<Vec<u16>> {
    (0..units)
        .map(|index| u16_at(data, offset.checked_add(index.checked_mul(UNIT_BYTES)?)?))
        .collect()
}


fn block_at(data: &[u8], offset: usize) -> Option<Block> {
    let length = usize::from(u16_at(data, offset)?);
    let value_units = usize::from(u16_at(data, offset.checked_add(UNIT_BYTES)?)?);
    let end = offset.checked_add(length)?;
    let key_start = offset.checked_add(BLOCK_HEADER_BYTES)?;
    (length >= BLOCK_HEADER_BYTES && end <= data.len()).then_some(())?;
    let key_units = (0..MAX_KEY_UNITS)
        .map_while(|index| u16_at(data, key_start.checked_add(index.checked_mul(UNIT_BYTES)?)?))
        .take_while(|unit| *unit != 0)
        .collect::<Vec<_>>();
    let key_end = key_start.checked_add(key_units.len().checked_add(1)?.checked_mul(UNIT_BYTES)?)?;
    (key_end <= end).then_some(())?;
    Some(Block {
        end,
        key: String::from_utf16(&key_units).ok()?,
        value_offset: align_word(key_end),
        value_units,
    })
}


fn children(data: &[u8], start: usize, end: usize) -> impl Iterator<Item = Block> + '_ {
    std::iter::successors(Some(start), move |offset| {
        block_at(data, *offset).map(|block| align_word(block.end)).filter(|next| *next < end)
    })
    .take(MAX_BLOCKS)
    .filter_map(|offset| block_at(data, offset))
}


fn string_value(data: &[u8], block: &Block) -> Option<String> {
    (block.value_units <= MAX_STRING_UNITS).then_some(())?;
    let units = utf16_at(data, block.value_offset, block.value_units)?;
    let text_units = units.split(|unit| *unit == 0).next().unwrap_or(&[]);
    String::from_utf16(text_units).ok()
}


fn named_string(data: &[u8], table: &Block, name: &str) -> Option<String> {
    children(data, table.value_offset, table.end)
        .find(|entry| entry.key == name)
        .and_then(|entry| string_value(data, &entry))
}


fn fixed_version(data: &[u8], root: &Block) -> Option<VersionParts> {
    let value_bytes = u16_at(data, UNIT_BYTES)?;
    (value_bytes == FIXED_INFO_BYTES && root.key == ROOT_KEY).then_some(())?;
    (u32_at(data, root.value_offset)? == FIXED_INFO_SIGNATURE).then_some(())?;
    let most = u32_at(data, root.value_offset.checked_add(FIXED_VERSION_OFFSET)?)?;
    let least = u32_at(data, root.value_offset.checked_add(FIXED_VERSION_OFFSET + WORD_BYTES)?)?;
    let (major, minor) = split_half(most);
    let (build, revision) = split_half(least);
    Some([major, minor, build, revision])
}


fn split_half(value: u32) -> (u16, u16) {
    let [first, second, third, fourth] = value.to_be_bytes();
    (u16::from_be_bytes([first, second]), u16::from_be_bytes([third, fourth]))
}


fn version_from_data(data: &[u8]) -> Option<VersionInfo> {
    let root = block_at(data, 0)?;
    let fixed = fixed_version(data, &root)?;
    let after_fixed = align_word(root.value_offset.checked_add(usize::from(FIXED_INFO_BYTES))?);
    let info = children(data, after_fixed, root.end).find(|block| block.key == STRING_FILE_INFO)?;
    let table = children(data, info.value_offset, info.end).next()?;
    Some(VersionInfo {
        original_file_name: named_string(data, &table, KEY_ORIGINAL_FILE_NAME),
        internal_name: named_string(data, &table, KEY_INTERNAL_NAME),
        product_name: named_string(data, &table, KEY_PRODUCT_NAME),
        file_description: named_string(data, &table, KEY_FILE_DESCRIPTION),
        company_name: named_string(data, &table, KEY_COMPANY_NAME),
        file_version: fixed,
        file_version_text: named_string(data, &table, KEY_FILE_VERSION),
    })
}


/// Reads the name strings (each optional) and the fixed file version from the PE version resource of `bytes` (the bytes the digest covers), every offset bounded.
pub fn parse_version(bytes: &[u8]) -> Result<VersionInfo, SignatureError> {
    version_data(bytes).and_then(version_from_data).ok_or(SignatureError::NoVersionInfo)
}
