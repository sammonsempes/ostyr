use crate::build::{ace, acl, acl_raw, descriptor, descriptor_raw, object_ace, raw_ace, sid_bytes, DACL_PRESENT, SELF_RELATIVE};
use crate::types::TestResult;
use sys_windows::descriptor::{parse_acl, parse_descriptor, sid_from_token_user, sid_to_string};
use sys_windows::types::{Ace, DirAclError};


const SYSTEM: &str = "S-1-5-18";


const USERS: &str = "S-1-5-32-545";


const WRITE_MASK: u32 = 0x0012_0116;


const BOTH_OBJECT_GUIDS: u32 = 3;


const ONE_OBJECT_GUID: u32 = 1;


const NO_OBJECT_GUID: u32 = 0;


const KIND_ALLOWED: u8 = 0;


const KIND_DENIED: u8 = 1;


const KIND_AUDIT: u8 = 2;


const KIND_ALLOWED_OBJECT: u8 = 5;


const KIND_ALLOWED_CALLBACK: u8 = 9;


const KIND_ALLOWED_CALLBACK_OBJECT: u8 = 0xB;


const INHERIT_FLAGS: u8 = 0x13;


const AUTHORITY_LIMIT_TEXT: &str = "S-1-0x100000000-1";


const BAD_REVISION: u8 = 2;


const TOO_MANY_SUBAUTHORITIES: u8 = 16;


const AUTHORITY_LIMIT_HEX: &str = "S-1-0x000100000000-1";


const ACL_HEADER_SIZE: u16 = 8;


const DESCRIPTOR_HEADER_SIZE: u32 = 20;


const SECOND_BYTE: usize = 1;


const WORD: usize = 4;


const PAIR: usize = 2;


const OWNER_OFFSET_BEYOND: u32 = 4096;


const ACE_HEADER_ONLY: u16 = 4;


const SHORT_ENTRY: usize = 3;


const OVERSIZED_ENTRY: u16 = 200;


const OVERSIZED_ACL: u16 = 500;


const TWO_ENTRIES: u16 = 2;


const POINTER_BYTES: usize = std::mem::size_of::<usize>();


const BASE_ADDRESS: usize = 0x1000;


#[test]
fn well_known_sids_have_their_string_form() -> TestResult {
    assert_eq!(sid_to_string(&sid_bytes(SYSTEM)?)?, SYSTEM);
    assert_eq!(sid_to_string(&sid_bytes(USERS)?)?, USERS);
    assert_eq!(sid_to_string(&sid_bytes("S-1-1-0")?)?, "S-1-1-0");
    Ok(())
}


#[test]
fn a_large_authority_is_written_in_hexadecimal_and_trailing_bytes_are_ignored() -> TestResult {
    assert_eq!(sid_to_string(&sid_bytes(AUTHORITY_LIMIT_TEXT)?)?, AUTHORITY_LIMIT_HEX);
    let mut padded = sid_bytes(SYSTEM)?;
    padded.push(1);
    assert_eq!(sid_to_string(&padded)?, SYSTEM);
    Ok(())
}


#[test]
fn a_malformed_sid_is_refused() -> TestResult {
    assert!(matches!(sid_to_string(&[]), Err(DirAclError::InvalidSid(_))));
    assert!(matches!(sid_to_string(&[1, 1, 0]), Err(DirAclError::InvalidSid(_))));
    let mut wrong_revision = sid_bytes(SYSTEM)?;
    set_byte(&mut wrong_revision, 0, BAD_REVISION);
    assert!(matches!(sid_to_string(&wrong_revision), Err(DirAclError::InvalidSid(_))));
    let mut too_many = sid_bytes(SYSTEM)?;
    set_byte(&mut too_many, SECOND_BYTE, TOO_MANY_SUBAUTHORITIES);
    assert!(matches!(sid_to_string(&too_many), Err(DirAclError::InvalidSid(_))));
    let mut truncated = sid_bytes(USERS)?;
    truncated.pop();
    assert!(matches!(sid_to_string(&truncated), Err(DirAclError::InvalidSid(_))));
    Ok(())
}


#[test]
fn allow_entries_are_parsed_in_every_layout() -> TestResult {
    let entries = [
        ace(KIND_ALLOWED, INHERIT_FLAGS, WRITE_MASK, USERS)?,
        ace(KIND_ALLOWED_CALLBACK, 0, WRITE_MASK, SYSTEM)?,
        object_ace(KIND_ALLOWED_OBJECT, WRITE_MASK, BOTH_OBJECT_GUIDS, USERS)?,
        object_ace(KIND_ALLOWED_CALLBACK_OBJECT, WRITE_MASK, ONE_OBJECT_GUID, USERS)?,
        object_ace(KIND_ALLOWED_OBJECT, WRITE_MASK, NO_OBJECT_GUID, SYSTEM)?,
    ];
    let parsed = parse_acl(&acl(&entries)?)?;
    let found: Vec<(u8, u8, &str, u32)> = parsed
        .iter()
        .map(|entry| (entry.kind, entry.flags, entry.sid.as_str(), entry.mask))
        .collect();
    assert_eq!(
        found,
        vec![
            (KIND_ALLOWED, INHERIT_FLAGS, USERS, WRITE_MASK),
            (KIND_ALLOWED_CALLBACK, 0, SYSTEM, WRITE_MASK),
            (KIND_ALLOWED_OBJECT, 0, USERS, WRITE_MASK),
            (KIND_ALLOWED_CALLBACK_OBJECT, 0, USERS, WRITE_MASK),
            (KIND_ALLOWED_OBJECT, 0, SYSTEM, WRITE_MASK),
        ]
    );
    Ok(())
}


#[test]
fn other_entries_keep_only_their_type_and_flags() -> TestResult {
    let entries = [
        raw_ace(KIND_DENIED, INHERIT_FLAGS, ACE_HEADER_ONLY, &[]),
        raw_ace(KIND_AUDIT, 0, ACE_HEADER_ONLY, &[]),
    ];
    let parsed = parse_acl(&acl(&entries)?)?;
    assert_eq!(
        parsed,
        vec![
            Ace {
                kind: KIND_DENIED,
                flags: INHERIT_FLAGS,
                sid: String::new(),
                mask: 0
            },
            Ace {
                kind: KIND_AUDIT,
                flags: 0,
                sid: String::new(),
                mask: 0
            },
        ]
    );
    assert!(parse_acl(&acl(&[])?)?.is_empty());
    Ok(())
}


#[test]
fn a_malformed_acl_is_refused() -> TestResult {
    assert!(matches!(parse_acl(&[]), Err(DirAclError::Malformed(_))));
    assert!(matches!(parse_acl(&acl_raw(OVERSIZED_ACL, 0, &[])), Err(DirAclError::Malformed(_))));
    assert!(matches!(parse_acl(&acl_raw(ACL_HEADER_SIZE, 1, &[])), Err(DirAclError::Malformed(_))));
    let short = vec![KIND_ALLOWED; SHORT_ENTRY];
    let short_size = u16::try_from(usize::from(ACL_HEADER_SIZE) + SHORT_ENTRY)?;
    assert!(matches!(parse_acl(&acl_raw(short_size, 1, &short)), Err(DirAclError::Malformed(_))));
    let undersized = raw_ace(KIND_DENIED, 0, 1, &[]);
    assert!(matches!(parse_acl(&acl(&[undersized])?), Err(DirAclError::Malformed(_))));
    let oversized = raw_ace(KIND_DENIED, 0, OVERSIZED_ENTRY, &[]);
    assert!(matches!(parse_acl(&acl(&[oversized])?), Err(DirAclError::Malformed(_))));
    let no_mask = raw_ace(KIND_ALLOWED, 0, ACE_HEADER_ONLY, &[]);
    assert!(matches!(parse_acl(&acl(&[no_mask])?), Err(DirAclError::Malformed(_))));
    let no_object_flags = raw_ace(KIND_ALLOWED_OBJECT, 0, ACE_HEADER_ONLY, &[]);
    assert!(matches!(parse_acl(&acl(&[no_object_flags])?), Err(DirAclError::Malformed(_))));
    let no_sid = raw_ace(KIND_ALLOWED, 0, ACE_HEADER_ONLY + ACE_HEADER_ONLY, &[0; WORD]);
    assert!(matches!(parse_acl(&acl(&[no_sid])?), Err(DirAclError::InvalidSid(_))));
    let count_without_entries = acl_raw(ACL_HEADER_SIZE + TWO_ENTRIES, TWO_ENTRIES, &[0; PAIR]);
    assert!(matches!(parse_acl(&count_without_entries), Err(DirAclError::Malformed(_))));
    Ok(())
}


#[test]
fn a_descriptor_gives_its_owner_and_its_dacl() -> TestResult {
    let list = acl(&[ace(KIND_ALLOWED, 0, WRITE_MASK, USERS)?])?;
    let bytes = descriptor(SELF_RELATIVE | DACL_PRESENT, &sid_bytes(SYSTEM)?, Some(&list))?;
    let parsed = parse_descriptor(&bytes)?;
    assert_eq!(parsed.owner, SYSTEM);
    assert_eq!(parsed.dacl.map(|entries| entries.len()), Some(1));
    Ok(())
}


#[test]
fn a_descriptor_without_a_dacl_has_none() -> TestResult {
    let owner = sid_bytes(SYSTEM)?;
    let list = acl(&[])?;
    assert_eq!(parse_descriptor(&descriptor(SELF_RELATIVE, &owner, Some(&list))?)?.dacl, None);
    assert_eq!(parse_descriptor(&descriptor(SELF_RELATIVE | DACL_PRESENT, &owner, None)?)?.dacl, None);
    assert_eq!(
        parse_descriptor(&descriptor(SELF_RELATIVE | DACL_PRESENT, &owner, Some(&list))?)?.dacl,
        Some(Vec::new())
    );
    Ok(())
}


#[test]
fn a_malformed_descriptor_is_refused() -> TestResult {
    let owner = sid_bytes(SYSTEM)?;
    assert!(matches!(parse_descriptor(&[]), Err(DirAclError::Malformed(_))));
    assert!(matches!(
        parse_descriptor(&descriptor(DACL_PRESENT, &owner, None)?),
        Err(DirAclError::Malformed(_))
    ));
    assert!(matches!(
        parse_descriptor(&descriptor_raw(SELF_RELATIVE, 0, 0, &owner)),
        Err(DirAclError::Malformed(_))
    ));
    assert!(matches!(
        parse_descriptor(&descriptor_raw(SELF_RELATIVE, OWNER_OFFSET_BEYOND, 0, &owner)),
        Err(DirAclError::Malformed(_))
    ));
    assert!(matches!(
        parse_descriptor(&descriptor_raw(SELF_RELATIVE, DESCRIPTOR_HEADER_SIZE, 0, &[])),
        Err(DirAclError::InvalidSid(_))
    ));
    assert!(matches!(
        parse_descriptor(&descriptor_raw(
            SELF_RELATIVE | DACL_PRESENT,
            DESCRIPTOR_HEADER_SIZE,
            OWNER_OFFSET_BEYOND,
            &owner
        )),
        Err(DirAclError::Malformed(_))
    ));
    let broken_list = acl_raw(OVERSIZED_ACL, 0, &[]);
    assert!(matches!(
        parse_descriptor(&descriptor(SELF_RELATIVE | DACL_PRESENT, &owner, Some(&broken_list))?),
        Err(DirAclError::Malformed(_))
    ));
    Ok(())
}


fn set_byte(bytes: &mut [u8], index: usize, value: u8) {
    if let Some(byte) = bytes.get_mut(index) {
        *byte = value;
    }
}


fn token_user_buffer(base: usize, sid: &[u8]) -> Vec<u8> {
    let mut buffer = (base + POINTER_BYTES + POINTER_BYTES).to_le_bytes().to_vec();
    buffer.extend(vec![0; POINTER_BYTES]);
    buffer.extend(sid);
    buffer
}


#[test]
fn the_token_user_sid_is_read_through_its_own_pointer() -> TestResult {
    let buffer = token_user_buffer(BASE_ADDRESS, &sid_bytes(SYSTEM)?);
    assert_eq!(sid_from_token_user(&buffer, BASE_ADDRESS)?, SYSTEM);
    Ok(())
}


#[test]
fn a_token_user_pointer_outside_its_buffer_is_refused() -> TestResult {
    let buffer = token_user_buffer(BASE_ADDRESS, &sid_bytes(SYSTEM)?);
    assert!(matches!(
        sid_from_token_user(&buffer, BASE_ADDRESS + BASE_ADDRESS),
        Err(DirAclError::Malformed(_))
    ));
    assert!(matches!(sid_from_token_user(&buffer, 0), Err(DirAclError::Malformed(_))));
    assert!(matches!(sid_from_token_user(&[], 0), Err(DirAclError::Malformed(_))));
    Ok(())
}
