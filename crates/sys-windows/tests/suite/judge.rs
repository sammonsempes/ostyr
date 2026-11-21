use crate::types::TestResult;
use std::path::Path;
use sys_windows::judge::{
    judge_spool_dir, map_generic, principals_from_token_user, refused_bits, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, GENERIC_ALL, GENERIC_EXECUTE, GENERIC_READ, GENERIC_WRITE, READ_ONLY_RIGHTS,
};
use sys_windows::types::{Ace, DirAclError, ParsedDescriptor, Principals};


const SYSTEM: &str = "S-1-5-18";


const ADMINISTRATORS: &str = "S-1-5-32-544";


const USERS: &str = "S-1-5-32-545";


const EVERYONE: &str = "S-1-1-0";


const AUTHENTICATED_USERS: &str = "S-1-5-11";


const LOCAL_SERVICE: &str = "S-1-5-19";


const NETWORK_SERVICE: &str = "S-1-5-20";


const SERVICE_ACCOUNT: &str = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";


const STANDARD_USER: &str = "S-1-5-21-1-2-3-1001";


const CREATOR_OWNER: &str = "S-1-3-0";


const OWNER_RIGHTS: &str = "S-1-3-4";


const KIND_ALLOWED: u8 = 0x0;


const KIND_DENIED: u8 = 0x1;


const KIND_AUDIT: u8 = 0x2;


const KIND_ALLOWED_OBJECT: u8 = 0x5;


const KIND_DENIED_OBJECT: u8 = 0x6;


const KIND_ALLOWED_CALLBACK: u8 = 0x9;


const KIND_DENIED_CALLBACK: u8 = 0xA;


const KIND_ALLOWED_CALLBACK_OBJECT: u8 = 0xB;


const KIND_DENIED_CALLBACK_OBJECT: u8 = 0xC;


const OBJECT_INHERIT: u8 = 0x01;


const CONTAINER_INHERIT: u8 = 0x02;


const INHERIT_ONLY: u8 = 0x08;


const INHERITED: u8 = 0x10;


const FILE_ADD_FILE: u32 = 0x0002;


const DELETE: u32 = 0x0001_0000;


const WRITE_DAC: u32 = 0x0004_0000;


const WRITE_OWNER: u32 = 0x0008_0000;


const MAXIMUM_ALLOWED: u32 = 0x0200_0000;


const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;


const RESERVED_BIT: u32 = 0x0400_0000;


const ACCESS_DENIED: u32 = 5;


const GENERIC_WRITE_BITS: u32 = 0x0000_0116;


fn allow(sid: &str, mask: u32) -> Ace {
    allow_with(KIND_ALLOWED, 0, sid, mask)
}


fn allow_with(kind: u8, flags: u8, sid: &str, mask: u32) -> Ace {
    Ace {
        kind,
        flags,
        sid: sid.to_owned(),
        mask,
    }
}


fn descriptor(owner: &str, aces: Vec<Ace>) -> ParsedDescriptor {
    ParsedDescriptor {
        owner: owner.to_owned(),
        dacl: Some(aces),
    }
}


fn judge_as(token_user: &str, descriptor: &ParsedDescriptor) -> Result<(), DirAclError> {
    judge_spool_dir(Path::new("spool"), descriptor, &principals_from_token_user(token_user)?)
}


fn untrusted(result: Result<(), DirAclError>) -> Option<(String, u32)> {
    match result {
        Err(DirAclError::UntrustedAce { sid, bits, .. }) => Some((sid, bits)),
        _ => None,
    }
}


#[test]
fn system_and_a_service_sid_are_the_agent_account() -> TestResult {
    assert!(principals_from_token_user(SYSTEM)?.trusted.iter().any(|sid| sid == SYSTEM));
    let service = principals_from_token_user(SERVICE_ACCOUNT)?;
    assert!(service.trusted.iter().any(|sid| sid == SERVICE_ACCOUNT));
    assert!(service.trusted.iter().any(|sid| sid == ADMINISTRATORS));
    Ok(())
}


#[test]
fn local_service_network_service_and_users_are_never_the_agent_account() -> TestResult {
    [LOCAL_SERVICE, NETWORK_SERVICE, STANDARD_USER, USERS, EVERYONE]
        .iter()
        .try_for_each(|sid| {
            let principals = principals_from_token_user(sid)?;
            assert!(!principals.trusted.iter().any(|trusted| trusted == sid), "{sid} was trusted");
            Ok::<(), DirAclError>(())
        })?;
    Ok(())
}


#[test]
fn a_token_user_that_is_not_a_sid_is_refused() -> TestResult {
    assert!(matches!(principals_from_token_user("labadmin"), Err(DirAclError::InvalidSid(_))));
    Ok(())
}


#[test]
fn generic_rights_map_to_the_file_rights() -> TestResult {
    assert_eq!(map_generic(GENERIC_READ), FILE_GENERIC_READ);
    assert_eq!(map_generic(GENERIC_WRITE), FILE_GENERIC_WRITE);
    assert_eq!(map_generic(GENERIC_EXECUTE), FILE_GENERIC_EXECUTE);
    assert_eq!(map_generic(GENERIC_ALL), FILE_ALL_ACCESS);
    assert_eq!(map_generic(DELETE | GENERIC_READ), DELETE | FILE_GENERIC_READ);
    assert_eq!(map_generic(MAXIMUM_ALLOWED), MAXIMUM_ALLOWED);
    Ok(())
}


#[test]
fn only_read_rights_pass_the_mask_check() -> TestResult {
    assert_eq!(refused_bits(READ_ONLY_RIGHTS), 0);
    assert_eq!(refused_bits(GENERIC_READ | GENERIC_EXECUTE), 0);
    assert_eq!(refused_bits(GENERIC_WRITE), GENERIC_WRITE_BITS);
    assert_eq!(refused_bits(GENERIC_ALL), FILE_ALL_ACCESS & !READ_ONLY_RIGHTS);
    assert_eq!(refused_bits(MAXIMUM_ALLOWED), MAXIMUM_ALLOWED);
    assert_eq!(refused_bits(ACCESS_SYSTEM_SECURITY), ACCESS_SYSTEM_SECURITY);
    assert_eq!(refused_bits(RESERVED_BIT), RESERVED_BIT);
    Ok(())
}


#[test]
fn the_installer_layout_is_accepted() -> TestResult {
    let layout = descriptor(
        ADMINISTRATORS,
        vec![
            allow_with(KIND_ALLOWED, OBJECT_INHERIT | CONTAINER_INHERIT, SYSTEM, FILE_ALL_ACCESS),
            allow_with(KIND_ALLOWED, OBJECT_INHERIT | CONTAINER_INHERIT, ADMINISTRATORS, FILE_ALL_ACCESS),
            allow_with(
                KIND_ALLOWED,
                OBJECT_INHERIT | CONTAINER_INHERIT | INHERITED,
                USERS,
                GENERIC_READ | GENERIC_EXECUTE,
            ),
            allow(CREATOR_OWNER, FILE_ALL_ACCESS),
            allow(OWNER_RIGHTS, FILE_ALL_ACCESS),
        ],
    );
    judge_as(SYSTEM, &layout)?;
    Ok(())
}


#[test]
fn an_empty_dacl_is_accepted_and_a_null_dacl_is_refused() -> TestResult {
    judge_as(SYSTEM, &descriptor(SYSTEM, Vec::new()))?;
    let null = ParsedDescriptor {
        owner: SYSTEM.to_owned(),
        dacl: None,
    };
    assert!(matches!(judge_as(SYSTEM, &null), Err(DirAclError::NullDacl { .. })));
    Ok(())
}


#[test]
fn users_may_not_add_files_delete_or_change_the_acl() -> TestResult {
    [FILE_ADD_FILE, DELETE, WRITE_DAC, WRITE_OWNER].iter().for_each(|mask| {
        let found = untrusted(judge_as(SYSTEM, &descriptor(SYSTEM, vec![allow(USERS, *mask)])));
        assert_eq!(found, Some((USERS.to_owned(), *mask)));
    });
    Ok(())
}


#[test]
fn inheritance_flags_never_exempt_an_entry() -> TestResult {
    [
        OBJECT_INHERIT,
        CONTAINER_INHERIT,
        OBJECT_INHERIT | INHERIT_ONLY,
        INHERIT_ONLY | CONTAINER_INHERIT,
        INHERITED,
    ]
    .iter()
    .for_each(|flags| {
        let entry = allow_with(KIND_ALLOWED, *flags, USERS, GENERIC_WRITE);
        let found = untrusted(judge_as(SYSTEM, &descriptor(SYSTEM, vec![entry])));
        assert_eq!(found, Some((USERS.to_owned(), GENERIC_WRITE_BITS)), "flags {flags:#x}");
    });
    Ok(())
}


#[test]
fn generic_and_special_bits_are_refused() -> TestResult {
    [GENERIC_WRITE, GENERIC_ALL, MAXIMUM_ALLOWED, ACCESS_SYSTEM_SECURITY, RESERVED_BIT]
        .iter()
        .for_each(|mask| {
            let found = untrusted(judge_as(SYSTEM, &descriptor(SYSTEM, vec![allow(EVERYONE, *mask)])));
            assert_eq!(found.map(|entry| entry.1), Some(refused_bits(*mask)));
        });
    Ok(())
}


#[test]
fn read_and_execute_for_users_is_accepted() -> TestResult {
    judge_as(
        SYSTEM,
        &descriptor(
            SYSTEM,
            vec![allow(USERS, GENERIC_READ | GENERIC_EXECUTE), allow(EVERYONE, READ_ONLY_RIGHTS)],
        ),
    )?;
    Ok(())
}


#[test]
fn every_allow_layout_is_judged() -> TestResult {
    [KIND_ALLOWED, KIND_ALLOWED_OBJECT, KIND_ALLOWED_CALLBACK, KIND_ALLOWED_CALLBACK_OBJECT]
        .iter()
        .for_each(|kind| {
            let entry = allow_with(*kind, 0, USERS, FILE_ADD_FILE);
            assert_eq!(
                untrusted(judge_as(SYSTEM, &descriptor(SYSTEM, vec![entry]))),
                Some((USERS.to_owned(), FILE_ADD_FILE)),
                "kind {kind:#x}"
            );
        });
    Ok(())
}


#[test]
fn deny_entries_neither_cancel_an_allow_nor_are_judged() -> TestResult {
    let deny_then_allow = descriptor(
        SYSTEM,
        vec![
            allow_with(KIND_DENIED, 0, USERS, FILE_ALL_ACCESS),
            allow(AUTHENTICATED_USERS, FILE_ADD_FILE),
        ],
    );
    assert_eq!(
        untrusted(judge_as(SYSTEM, &deny_then_allow)),
        Some((AUTHENTICATED_USERS.to_owned(), FILE_ADD_FILE))
    );
    let same_sid = descriptor(
        SYSTEM,
        vec![allow_with(KIND_DENIED, 0, USERS, FILE_ALL_ACCESS), allow(USERS, FILE_ADD_FILE)],
    );
    assert_eq!(untrusted(judge_as(SYSTEM, &same_sid)), Some((USERS.to_owned(), FILE_ADD_FILE)));
    let only_denies = [KIND_DENIED, KIND_DENIED_OBJECT, KIND_DENIED_CALLBACK, KIND_DENIED_CALLBACK_OBJECT]
        .iter()
        .map(|kind| allow_with(*kind, 0, USERS, FILE_ALL_ACCESS))
        .collect();
    judge_as(SYSTEM, &descriptor(SYSTEM, only_denies))?;
    Ok(())
}


#[test]
fn an_unknown_entry_type_is_refused_even_for_a_trusted_sid() -> TestResult {
    let entry = allow_with(KIND_AUDIT, 0, SYSTEM, 0);
    assert!(matches!(
        judge_as(SYSTEM, &descriptor(SYSTEM, vec![entry])),
        Err(DirAclError::UnknownAceType { kind: KIND_AUDIT, .. })
    ));
    Ok(())
}


#[test]
fn the_owner_must_be_trusted() -> TestResult {
    let result = judge_as(SYSTEM, &descriptor(STANDARD_USER, vec![allow(SYSTEM, FILE_ALL_ACCESS)]));
    assert!(matches!(result, Err(DirAclError::UntrustedOwner { ref sid, .. }) if sid == STANDARD_USER));
    judge_as(SYSTEM, &descriptor(ADMINISTRATORS, Vec::new()))?;
    judge_as(SERVICE_ACCOUNT, &descriptor(SERVICE_ACCOUNT, Vec::new()))?;
    assert!(matches!(
        judge_as(SYSTEM, &descriptor(SERVICE_ACCOUNT, Vec::new())),
        Err(DirAclError::UntrustedOwner { .. })
    ));
    Ok(())
}


#[test]
fn local_service_is_refused_as_the_agent_account() -> TestResult {
    let owned = descriptor(LOCAL_SERVICE, vec![allow(LOCAL_SERVICE, FILE_ALL_ACCESS)]);
    assert_eq!(
        untrusted(judge_as(LOCAL_SERVICE, &owned)),
        Some((LOCAL_SERVICE.to_owned(), FILE_ALL_ACCESS & !READ_ONLY_RIGHTS))
    );
    let only_owner = descriptor(LOCAL_SERVICE, Vec::new());
    assert!(matches!(judge_as(LOCAL_SERVICE, &only_owner), Err(DirAclError::UntrustedOwner { .. })));
    Ok(())
}


#[test]
fn an_entry_refusal_is_reported_before_the_owner_refusal() -> TestResult {
    let mixed = descriptor(STANDARD_USER, vec![allow(USERS, FILE_ADD_FILE)]);
    assert!(matches!(judge_as(SYSTEM, &mixed), Err(DirAclError::UntrustedAce { .. })));
    Ok(())
}


#[test]
fn a_refusal_names_the_path_the_sid_and_the_bits() -> TestResult {
    let message = judge_as(SYSTEM, &descriptor(SYSTEM, vec![allow(USERS, FILE_ADD_FILE)])).map_err(|error| error.to_string());
    assert_eq!(
        message,
        Err("spool grants 0x00000002 to S-1-5-32-545, which is not a trusted principal".to_owned())
    );
    let owner = judge_as(SYSTEM, &descriptor(USERS, Vec::new())).map_err(|error| error.to_string());
    assert_eq!(owner, Err("spool is owned by S-1-5-32-545, which is not a trusted principal".to_owned()));
    let null = ParsedDescriptor {
        owner: SYSTEM.to_owned(),
        dacl: None,
    };
    assert!(judge_as(SYSTEM, &null)
        .map_err(|error| error.to_string())
        .err()
        .is_some_and(|text| text.starts_with("spool has a NULL DACL")));
    let unknown = judge_as(SYSTEM, &descriptor(SYSTEM, vec![allow_with(KIND_AUDIT, 0, SYSTEM, 0)])).map_err(|error| error.to_string());
    assert_eq!(unknown, Err("spool has an access control entry of unknown type 0x2".to_owned()));
    Ok(())
}


#[test]
fn the_other_errors_describe_themselves() -> TestResult {
    assert_eq!(DirAclError::InvalidSid("x").to_string(), "invalid SID: x");
    assert_eq!(DirAclError::Malformed("y").to_string(), "malformed security descriptor: y");
    assert_eq!(
        DirAclError::Windows {
            operation: "Op",
            code: ACCESS_DENIED
        }
        .to_string(),
        "Op failed with code 0x00000005"
    );
    Ok(())
}


#[test]
fn a_principal_set_is_plain_data() -> TestResult {
    let principals = Principals {
        trusted: vec![SYSTEM.to_owned()],
    };
    assert_eq!(principals.clone(), principals);
    Ok(())
}
