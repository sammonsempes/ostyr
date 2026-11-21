use crate::types::TestResult;
use std::path::{Path, PathBuf};
use sys_windows::judge::{principals_from_token_user, FILE_ALL_ACCESS, GENERIC_ALL, GENERIC_WRITE};
use sys_windows::types::{Ace, DirAclError, ParsedDescriptor};
use sys_windows::walk::{
    ancestor_principals, judge_ancestor, split_volume_path, walk_prefixes, ANCESTOR_FORBIDDEN_RIGHTS, DELETE, FILE_DELETE_CHILD, INHERIT_ONLY,
    SID_TRUSTED_INSTALLER, WRITE_DAC, WRITE_OWNER,
};


const BOTH_INHERIT: u8 = 0x03;


const CONTAINER_INHERIT: u8 = 0x02;


const AUTH_ROOT_ENTRY: u32 = 0x0004;


const AUTH_MODIFY_INHERIT: u32 = 0x0013_01BF;


const USERS_CREATE: u32 = 0x0114;


const KIND_AUDIT: u8 = 2;


const SYSTEM: &str = "S-1-5-18";


const ADMINISTRATORS: &str = "S-1-5-32-544";


const USERS: &str = "S-1-5-32-545";


const AUTHENTICATED_USERS: &str = "S-1-5-11";


const CREATOR_GROUP: &str = "S-1-3-1";


const CREATOR_OWNER: &str = "S-1-3-0";


const FILE_ADD_FILE_AND_SUBDIRECTORY: u32 = 0x0006;


const READ_EXECUTE: u32 = 0x0012_00A9;


const MAXIMUM_ALLOWED: u32 = 0x0200_0000;


const ACCESS_SYSTEM_SECURITY: u32 = 0x0100_0000;


fn allow(flags: u8, sid: &str, mask: u32) -> Ace {
    Ace {
        kind: 0,
        flags,
        sid: sid.to_string(),
        mask,
    }
}


fn judged(owner: &str, aces: Vec<Ace>) -> Result<(), DirAclError> {
    let principals = principals_from_token_user(SYSTEM)?;
    judge_ancestor(
        Path::new("C:\\ProgramData"),
        &ParsedDescriptor {
            owner: owner.to_string(),
            dacl: Some(aces),
        },
        &principals,
    )
}


fn fault(path: &str) -> Option<String> {
    split_volume_path(path).err().map(|error| error.to_string())
}


#[test]
fn a_local_absolute_path_is_split_into_root_and_components() -> TestResult {
    let split = split_volume_path("c:\\ProgramData\\Ostyr\\")?;
    assert_eq!(split.root, "C:\\");
    assert_eq!(split.components, ["ProgramData", "Ostyr"]);
    assert_eq!(split_volume_path("C:/ProgramData/Ostyr")?.components, ["ProgramData", "Ostyr"]);
    assert!(split_volume_path("C:\\")?.components.is_empty());
    assert!(split_volume_path("C:/")?.components.is_empty());
    Ok(())
}


#[test]
fn every_other_path_form_is_refused_by_name() -> TestResult {
    let cases = [
        ("\\\\?\\C:\\ProgramData", "no drive letter"),
        ("\\\\.\\C:\\ProgramData", "no drive letter"),
        ("\\\\host\\share\\dir", "no drive letter"),
        ("ProgramData\\Ostyr", "no drive letter"),
        ("", "no drive letter"),
        ("1:\\x", "no drive letter"),
        ("C", "no drive letter"),
        ("C:", "not rooted at the volume"),
        ("C:x\\y", "not rooted at the volume"),
        ("C:\\a\\..\\b", "dot component"),
        ("C:\\a\\.\\b", "dot component"),
        ("C:\\a\\\\b", "empty component"),
        ("C:\\\\a", "empty component"),
        ("C:\\a\\\\", "empty component"),
        ("C:\\a:stream", "forbidden character in a component"),
        ("C:\\a\\b*", "forbidden character in a component"),
        ("C:\\a\\b\u{1}c", "forbidden character in a component"),
        ("C:\\a\\Ostyr.", "component ends with a dot or a space"),
        ("C:\\a\\Ostyr ", "component ends with a dot or a space"),
    ];
    cases.iter().try_for_each(|(path, reason)| {
        let text = fault(path).ok_or("accepted")?;
        assert!(text.contains(reason), "{path:?}: {text}");
        assert!(text.contains("is not an absolute local path"), "{path:?}: {text}");
        Ok::<(), Box<dyn std::error::Error>>(())
    })?;
    Ok(())
}


#[test]
fn the_walk_opens_the_root_then_each_prefix() -> TestResult {
    let prefixes = walk_prefixes(&split_volume_path("C:\\ProgramData\\Ostyr\\sub")?);
    assert_eq!(
        prefixes,
        ["C:\\", "C:\\ProgramData", "C:\\ProgramData\\Ostyr", "C:\\ProgramData\\Ostyr\\sub"]
    );
    assert_eq!(walk_prefixes(&split_volume_path("C:\\")?), ["C:\\"]);
    Ok(())
}


#[test]
fn trusted_installer_joins_the_ancestor_principals_only() -> TestResult {
    let spool = principals_from_token_user(SYSTEM)?;
    assert!(!spool.trusted.contains(&SID_TRUSTED_INSTALLER.to_string()));
    assert!(ancestor_principals(&spool).trusted.contains(&SID_TRUSTED_INSTALLER.to_string()));
    Ok(())
}


#[test]
fn the_default_volume_root_and_program_data_acls_are_accepted() -> TestResult {
    judged(
        SID_TRUSTED_INSTALLER,
        vec![
            allow(0, AUTHENTICATED_USERS, AUTH_ROOT_ENTRY),
            allow(BOTH_INHERIT | INHERIT_ONLY, AUTHENTICATED_USERS, AUTH_MODIFY_INHERIT),
            allow(BOTH_INHERIT, SYSTEM, FILE_ALL_ACCESS),
            allow(BOTH_INHERIT, ADMINISTRATORS, FILE_ALL_ACCESS),
            allow(BOTH_INHERIT, USERS, READ_EXECUTE),
            allow(CONTAINER_INHERIT, USERS, FILE_ADD_FILE_AND_SUBDIRECTORY | USERS_CREATE),
            allow(BOTH_INHERIT | INHERIT_ONLY, CREATOR_OWNER, GENERIC_ALL),
        ],
    )?;
    judged(SYSTEM, vec![allow(BOTH_INHERIT, SID_TRUSTED_INSTALLER, FILE_ALL_ACCESS)])?;
    Ok(())
}


#[test]
fn an_untrusted_effective_entry_that_deletes_or_re_acls_is_refused() -> TestResult {
    [
        DELETE,
        FILE_DELETE_CHILD,
        WRITE_DAC,
        WRITE_OWNER,
        ACCESS_SYSTEM_SECURITY,
        MAXIMUM_ALLOWED,
        GENERIC_ALL,
        FILE_ALL_ACCESS,
    ]
    .iter()
    .for_each(|mask| {
        let verdict = judged(SYSTEM, vec![allow(0, USERS, *mask)]);
        assert!(
            matches!(&verdict, Err(DirAclError::UntrustedAce { sid, bits, .. }) if sid == USERS && bits & ANCESTOR_FORBIDDEN_RIGHTS != 0),
            "{mask:#x}: {verdict:?}"
        );
    });
    assert!(matches!(judged(SYSTEM, vec![allow(0, USERS, GENERIC_WRITE)]), Ok(())));
    Ok(())
}


#[test]
fn an_inherit_only_entry_and_a_deny_entry_are_not_effective() -> TestResult {
    judged(SYSTEM, vec![allow(INHERIT_ONLY, USERS, FILE_ALL_ACCESS)])?;
    let deny = Ace {
        kind: 1,
        flags: 0,
        sid: USERS.to_string(),
        mask: FILE_ALL_ACCESS,
    };
    judged(SYSTEM, vec![deny])?;
    Ok(())
}


#[test]
fn the_ancestor_owner_must_be_trusted_and_the_dacl_present() -> TestResult {
    assert!(matches!(judged(USERS, Vec::new()), Err(DirAclError::UntrustedOwner { .. })));
    judged(ADMINISTRATORS, Vec::new())?;
    let principals = principals_from_token_user(SYSTEM)?;
    let null = ParsedDescriptor {
        owner: SYSTEM.to_string(),
        dacl: None,
    };
    assert!(matches!(
        judge_ancestor(Path::new("C:\\x"), &null, &principals),
        Err(DirAclError::NullDacl { .. })
    ));
    Ok(())
}


#[test]
fn an_unknown_entry_type_is_refused_on_an_ancestor() -> TestResult {
    let audit = Ace {
        kind: KIND_AUDIT,
        flags: 0,
        sid: String::new(),
        mask: 0,
    };
    assert!(matches!(
        judged(SYSTEM, vec![audit]),
        Err(DirAclError::UnknownAceType { kind: KIND_AUDIT, .. })
    ));
    Ok(())
}


#[test]
fn creator_group_is_not_a_trusted_principal() -> TestResult {
    let principals = principals_from_token_user(SYSTEM)?;
    assert!(!principals.trusted.contains(&CREATOR_GROUP.to_string()));
    assert!(matches!(
        judged(SYSTEM, vec![allow(0, CREATOR_GROUP, FILE_ALL_ACCESS)]),
        Err(DirAclError::UntrustedAce { .. })
    ));
    Ok(())
}


#[test]
fn the_new_errors_describe_themselves() -> TestResult {
    let reparse = DirAclError::ReparsePoint {
        path: PathBuf::from("C:\\x"),
    };
    assert!(reparse.to_string().contains("reparse point"));
    let mismatch = DirAclError::IdentityMismatch {
        path: PathBuf::from("C:\\x"),
    };
    assert!(mismatch.to_string().contains("not the directory the walk judged"));
    let open = DirAclError::Open {
        path: PathBuf::from("C:\\x"),
        kind: std::io::ErrorKind::NotFound,
    };
    assert!(open.to_string().contains("NotFound"));
    Ok(())
}
