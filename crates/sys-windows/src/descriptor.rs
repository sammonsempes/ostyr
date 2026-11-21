use crate::types::{Ace, DirAclError, ParsedDescriptor};


pub const ACE_ALLOWED: u8 = 0x0;


pub const ACE_DENIED: u8 = 0x1;


pub const ACE_ALLOWED_OBJECT: u8 = 0x5;


pub const ACE_DENIED_OBJECT: u8 = 0x6;


pub const ACE_ALLOWED_CALLBACK: u8 = 0x9;


pub const ACE_DENIED_CALLBACK: u8 = 0xA;


pub const ACE_ALLOWED_CALLBACK_OBJECT: u8 = 0xB;


pub const ACE_DENIED_CALLBACK_OBJECT: u8 = 0xC;


const SID_REVISION: u8 = 1;


const SID_MAX_SUBAUTHORITIES: usize = 15;


const SID_HEADER_BYTES: usize = 8;


const SID_SUBAUTHORITY_BYTES: usize = 4;


const ACL_HEADER_BYTES: usize = 8;


const ACE_HEADER_BYTES: usize = 4;


const ACE_SID_OFFSET: usize = 8;


const ACE_OBJECT_SID_OFFSET: usize = 12;


const ACE_OBJECT_GUID_BYTES: usize = 16;


const ACE_OBJECT_TYPE_PRESENT: u32 = 0x1;


const ACE_OBJECT_INHERITED_TYPE_PRESENT: u32 = 0x2;


const DESCRIPTOR_HEADER_BYTES: usize = 20;


const CONTROL_DACL_PRESENT: u16 = 0x0004;


const CONTROL_SELF_RELATIVE: u16 = 0x8000;


const AUTHORITY_DECIMAL_LIMIT: u64 = 0xFFFF_FFFF;


const POINTER_BYTES: usize = std::mem::size_of::<usize>();


fn bytes_at<const LENGTH: usize>(bytes: &[u8], offset: usize) -> Option<[u8; LENGTH]> {
    bytes.get(offset..)?.get(..LENGTH)?.try_into().ok()
}


/// The string form (`S-1-5-18`) of the binary SID at the start of `bytes`; trailing bytes are ignored.
pub fn sid_to_string(bytes: &[u8]) -> Result<String, DirAclError> {
    let [revision, count_byte, a0, a1, a2, a3, a4, a5] = bytes_at::<SID_HEADER_BYTES>(bytes, 0).ok_or(DirAclError::InvalidSid("truncated header"))?;
    let authority = [a0, a1, a2, a3, a4, a5]
        .iter()
        .fold(0, |value: u64, byte| (value << u8::BITS) | u64::from(*byte));
    let count = usize::from(count_byte);
    (revision == SID_REVISION && count <= SID_MAX_SUBAUTHORITIES)
        .then_some(())
        .ok_or(DirAclError::InvalidSid("bad revision or subauthority count"))?;
    let subauthorities = (0..count)
        .map(|i| {
            bytes_at::<SID_SUBAUTHORITY_BYTES>(bytes, SID_HEADER_BYTES + i * SID_SUBAUTHORITY_BYTES)
                .map(u32::from_le_bytes)
                .ok_or(DirAclError::InvalidSid("truncated subauthority"))
        })
        .collect::<Result<Vec<u32>, DirAclError>>()?;
    let authority_text = if authority <= AUTHORITY_DECIMAL_LIMIT {
        authority.to_string()
    } else {
        format!("0x{authority:012X}")
    };
    Ok(subauthorities
        .iter()
        .fold(format!("S-{revision}-{authority_text}"), |text, part| format!("{text}-{part}")))
}


fn parse_ace(kind: u8, flags: u8, body: &[u8]) -> Result<Ace, DirAclError> {
    let truncated = DirAclError::Malformed("truncated access control entry");
    match kind {
        ACE_ALLOWED | ACE_ALLOWED_CALLBACK => {
            let [_, _, _, _, m0, m1, m2, m3] = bytes_at::<ACE_SID_OFFSET>(body, 0).ok_or(truncated)?;
            Ok(Ace {
                kind,
                flags,
                mask: u32::from_le_bytes([m0, m1, m2, m3]),
                sid: sid_to_string(body.get(ACE_SID_OFFSET..).unwrap_or(&[]))?,
            })
        }
        ACE_ALLOWED_OBJECT | ACE_ALLOWED_CALLBACK_OBJECT => {
            let [_, _, _, _, m0, m1, m2, m3, f0, f1, f2, f3] = bytes_at::<ACE_OBJECT_SID_OFFSET>(body, 0).ok_or(truncated)?;
            let object_flags = u32::from_le_bytes([f0, f1, f2, f3]);
            let guids = usize::from(object_flags & ACE_OBJECT_TYPE_PRESENT != 0) + usize::from(object_flags & ACE_OBJECT_INHERITED_TYPE_PRESENT != 0);
            let sid_offset = ACE_OBJECT_SID_OFFSET + guids * ACE_OBJECT_GUID_BYTES;
            Ok(Ace {
                kind,
                flags,
                mask: u32::from_le_bytes([m0, m1, m2, m3]),
                sid: sid_to_string(body.get(sid_offset..).unwrap_or(&[]))?,
            })
        }
        _ => Ok(Ace {
            kind,
            flags,
            sid: String::new(),
            mask: 0,
        }),
    }
}


/// Parses the ACL that starts at the beginning of `bytes`: allow entries fully, any other entry by its type and flags only.
pub fn parse_acl(bytes: &[u8]) -> Result<Vec<Ace>, DirAclError> {
    let [_, _, size_low, size_high, count_low, count_high, _, _] =
        bytes_at::<ACL_HEADER_BYTES>(bytes, 0).ok_or(DirAclError::Malformed("truncated ACL header"))?;
    let size = usize::from(u16::from_le_bytes([size_low, size_high]));
    let count = u16::from_le_bytes([count_low, count_high]);
    let acl = bytes.get(..size).ok_or(DirAclError::Malformed("ACL larger than its buffer"))?;
    let (_, aces) = (0..count).try_fold((ACL_HEADER_BYTES, Vec::new()), |(offset, mut aces), _| {
        let entry = acl.get(offset..).unwrap_or(&[]);
        let [kind, flags, entry_low, entry_high] =
            bytes_at::<ACE_HEADER_BYTES>(entry, 0).ok_or(DirAclError::Malformed("truncated access control entry"))?;
        let entry_size = usize::from(u16::from_le_bytes([entry_low, entry_high]));
        let body = entry
            .get(..entry_size)
            .filter(|_| entry_size >= ACE_HEADER_BYTES)
            .ok_or(DirAclError::Malformed("bad access control entry size"))?;
        aces.push(parse_ace(kind, flags, body)?);
        Ok::<_, DirAclError>((offset + entry_size, aces))
    })?;
    Ok(aces)
}


/// Parses a self-relative security descriptor (what `GetSecurityInfo` returns): owner SID and DACL.
pub fn parse_descriptor(bytes: &[u8]) -> Result<ParsedDescriptor, DirAclError> {
    let [_, _, c0, c1, o0, o1, o2, o3, _, _, _, _, _, _, _, _, d0, d1, d2, d3] =
        bytes_at::<DESCRIPTOR_HEADER_BYTES>(bytes, 0).ok_or(DirAclError::Malformed("truncated descriptor header"))?;
    let control = u16::from_le_bytes([c0, c1]);
    (control & CONTROL_SELF_RELATIVE != 0)
        .then_some(())
        .ok_or(DirAclError::Malformed("descriptor is not self-relative"))?;
    let owner_offset = usize::try_from(u32::from_le_bytes([o0, o1, o2, o3])).ok().filter(|offset| *offset != 0);
    let owner_bytes = owner_offset.and_then(|offset| bytes.get(offset..));
    let owner = sid_to_string(owner_bytes.ok_or(DirAclError::Malformed("no owner"))?)?;
    let dacl_offset = usize::try_from(u32::from_le_bytes([d0, d1, d2, d3])).ok().filter(|offset| *offset != 0);
    let present = control & CONTROL_DACL_PRESENT != 0;
    let dacl = dacl_offset
        .filter(|_| present)
        .map(|offset| {
            bytes
                .get(offset..)
                .ok_or(DirAclError::Malformed("DACL outside the descriptor"))
                .and_then(parse_acl)
        })
        .transpose()?;
    Ok(ParsedDescriptor { owner, dacl })
}


/// The user SID string of a `TOKEN_USER` buffer whose first field points inside the buffer itself; `base` is the address of the buffer.
pub fn sid_from_token_user(buffer: &[u8], base: usize) -> Result<String, DirAclError> {
    let pointer = bytes_at::<POINTER_BYTES>(buffer, 0).map(usize::from_le_bytes);
    let offset = pointer.and_then(|address| address.checked_sub(base));
    let sid = offset.and_then(|start| buffer.get(start..));
    sid_to_string(sid.ok_or(DirAclError::Malformed("token user SID outside its buffer"))?)
}
