use std::error::Error;


const AUTHORITY_SKIP: usize = 2;


const ACE_FIXED_BYTES: usize = 8;


const OBJECT_FIXED_BYTES: usize = 12;


const GUID_BYTES: usize = 16;


const ACL_HEADER: usize = 8;


const DESCRIPTOR_HEADER: usize = 20;


const ACL_REVISION: u8 = 2;


const DESCRIPTOR_REVISION: u8 = 1;


const HEX_RADIX: u32 = 16;


const WORD_BYTES: usize = 4;


const PAIR_BYTES: usize = 2;


const OBJECT_TYPE_FLAG: u32 = 1;


const INHERITED_TYPE_FLAG: u32 = 2;


pub const SELF_RELATIVE: u16 = 0x8000;


pub const DACL_PRESENT: u16 = 0x0004;


pub fn sid_bytes(text: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut parts = text.split('-').skip(1);
    let revision: u8 = parts.next().ok_or("revision")?.parse()?;
    let authority_text = parts.next().ok_or("authority")?;
    let authority = match authority_text.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, HEX_RADIX)?,
        None => authority_text.parse()?,
    };
    let subauthorities = parts.map(str::parse::<u32>).collect::<Result<Vec<u32>, _>>()?;
    let mut bytes = vec![revision, u8::try_from(subauthorities.len())?];
    bytes.extend(authority.to_be_bytes().iter().skip(AUTHORITY_SKIP));
    subauthorities.iter().for_each(|part| bytes.extend(part.to_le_bytes()));
    Ok(bytes)
}


pub fn ace(kind: u8, flags: u8, mask: u32, sid: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let sid_binary = sid_bytes(sid)?;
    let mut bytes = vec![kind, flags];
    bytes.extend(u16::try_from(ACE_FIXED_BYTES + sid_binary.len())?.to_le_bytes());
    bytes.extend(mask.to_le_bytes());
    bytes.extend(sid_binary);
    Ok(bytes)
}


pub fn object_ace(kind: u8, mask: u32, object_flags: u32, sid: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    let sid_binary = sid_bytes(sid)?;
    let guids = usize::from(object_flags & OBJECT_TYPE_FLAG != 0) + usize::from(object_flags & INHERITED_TYPE_FLAG != 0);
    let size = OBJECT_FIXED_BYTES + guids * GUID_BYTES + sid_binary.len();
    let mut bytes = vec![kind, 0];
    bytes.extend(u16::try_from(size)?.to_le_bytes());
    bytes.extend(mask.to_le_bytes());
    bytes.extend(object_flags.to_le_bytes());
    bytes.extend(vec![0; guids * GUID_BYTES]);
    bytes.extend(sid_binary);
    Ok(bytes)
}


pub fn raw_ace(kind: u8, flags: u8, declared_size: u16, body: &[u8]) -> Vec<u8> {
    let mut bytes = vec![kind, flags];
    bytes.extend(declared_size.to_le_bytes());
    bytes.extend(body);
    bytes
}


pub fn acl(aces: &[Vec<u8>]) -> Result<Vec<u8>, Box<dyn Error>> {
    let entries = aces.concat();
    Ok(acl_raw(u16::try_from(ACL_HEADER + entries.len())?, u16::try_from(aces.len())?, &entries))
}


pub fn acl_raw(size: u16, count: u16, entries: &[u8]) -> Vec<u8> {
    let mut bytes = vec![ACL_REVISION, 0];
    bytes.extend(size.to_le_bytes());
    bytes.extend(count.to_le_bytes());
    bytes.extend(vec![0; PAIR_BYTES]);
    bytes.extend(entries);
    bytes
}


pub fn descriptor_raw(control: u16, owner_offset: u32, dacl_offset: u32, tail: &[u8]) -> Vec<u8> {
    let mut bytes = vec![DESCRIPTOR_REVISION, 0];
    bytes.extend(control.to_le_bytes());
    bytes.extend(owner_offset.to_le_bytes());
    bytes.extend(vec![0; WORD_BYTES]);
    bytes.extend(vec![0; WORD_BYTES]);
    bytes.extend(dacl_offset.to_le_bytes());
    bytes.extend(tail);
    bytes
}


pub fn descriptor(control: u16, owner: &[u8], dacl: Option<&[u8]>) -> Result<Vec<u8>, Box<dyn Error>> {
    let owner_offset = u32::try_from(DESCRIPTOR_HEADER)?;
    let dacl_offset = dacl.map_or(Ok(0), |_| u32::try_from(DESCRIPTOR_HEADER + owner.len()))?;
    let tail = [owner, dacl.unwrap_or(&[])].concat();
    Ok(descriptor_raw(control, owner_offset, dacl_offset, &tail))
}
