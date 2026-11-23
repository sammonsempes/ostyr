use crate::support::{fakes_with, forbidden_spawn, hold_script, owner_of, private_tempdir, Fakes};
use crate::types::TestResult;
use agent_shell::account::{
    groups_in, lookup_account, lookup_groups, lookup_in, lookup_primary, primary_in, resolve_account, stat_home, AccountEntry, GroupEntry, HomeFacts,
    PrimaryGroup,
};
use agent_shell::compose::production_env;
use agent_shell::error::AccountError;
use agent_shell::model::{ShellHooks, ROOT_UID};
use std::io;
use std::path::{Path, PathBuf};


const ACCOUNT_UID: u32 = 1001;


const ACCOUNT_GID: u32 = 1002;


const UNUSED_GID: u32 = 3_999_999_999;


const DISK_GID: u32 = 6;


const USERS_GID: u32 = 100;


const UNKNOWN_GID: u32 = 77;


const NAME: &str = "ostyr-shell";


const HOME: &str = "/home/ostyr-shell";


fn entry(uid: u32, gid: u32) -> io::Result<Option<AccountEntry>> {
    Ok(Some(AccountEntry {
        uid,
        gid,
        home: PathBuf::from(HOME),
    }))
}


fn good_entry(_name: &str) -> io::Result<Option<AccountEntry>> {
    entry(ACCOUNT_UID, ACCOUNT_GID)
}


fn root_uid(_name: &str) -> io::Result<Option<AccountEntry>> {
    entry(0, ACCOUNT_GID)
}


fn root_gid(_name: &str) -> io::Result<Option<AccountEntry>> {
    entry(ACCOUNT_UID, 0)
}


fn absent(_name: &str) -> io::Result<Option<AccountEntry>> {
    Ok(None)
}


fn broken(_name: &str) -> io::Result<Option<AccountEntry>> {
    Err(io::Error::other("database down"))
}


fn no_groups(_name: &str) -> io::Result<Vec<String>> {
    Ok(Vec::new())
}


fn harmless_group(_name: &str) -> io::Result<Vec<String>> {
    Ok(vec!["users".to_owned()])
}


fn root_group(_name: &str) -> io::Result<Vec<String>> {
    Ok(vec!["root".to_owned(), "disk".to_owned()])
}


fn groups_down(_name: &str) -> io::Result<Vec<String>> {
    Err(io::Error::other("group database down"))
}


fn own_primary(name: &str, _gid: u32) -> io::Result<PrimaryGroup> {
    Ok(PrimaryGroup {
        entries: vec![GroupEntry {
            name: name.to_owned(),
            has_members: false,
        }],
        other_users: 0,
    })
}


fn primary_of(entries: Vec<GroupEntry>, other_users: usize) -> io::Result<PrimaryGroup> {
    Ok(PrimaryGroup { entries, other_users })
}


fn named_group(name: &str, has_members: bool) -> GroupEntry {
    GroupEntry {
        name: name.to_owned(),
        has_members,
    }
}


fn disk_primary(_name: &str, _gid: u32) -> io::Result<PrimaryGroup> {
    primary_of(vec![named_group("disk", false)], 0)
}


fn members_primary(name: &str, _gid: u32) -> io::Result<PrimaryGroup> {
    primary_of(vec![named_group(name, true)], 0)
}


fn shared_primary(name: &str, _gid: u32) -> io::Result<PrimaryGroup> {
    primary_of(vec![named_group(name, false)], 1)
}


fn absent_primary(_name: &str, _gid: u32) -> io::Result<PrimaryGroup> {
    primary_of(Vec::new(), 0)
}


fn twin_primary(name: &str, _gid: u32) -> io::Result<PrimaryGroup> {
    primary_of(vec![named_group(name, false), named_group(name, false)], 0)
}


fn primary_down(_name: &str, _gid: u32) -> io::Result<PrimaryGroup> {
    Err(io::Error::other("group database down"))
}


fn owned_directory(_home: &Path) -> io::Result<HomeFacts> {
    Ok(HomeFacts {
        is_directory: true,
        owner: ACCOUNT_UID,
    })
}


fn foreign_directory(_home: &Path) -> io::Result<HomeFacts> {
    Ok(HomeFacts {
        is_directory: true,
        owner: ACCOUNT_UID + 1,
    })
}


fn owned_file(_home: &Path) -> io::Result<HomeFacts> {
    Ok(HomeFacts {
        is_directory: false,
        owner: ACCOUNT_UID,
    })
}


fn unreadable(_home: &Path) -> io::Result<HomeFacts> {
    Err(io::Error::from(io::ErrorKind::PermissionDenied))
}


#[test]
fn the_account_is_resolved_once_with_its_ids_and_home() -> TestResult {
    let account = resolve_account(NAME, good_entry, no_groups, own_primary, owned_directory)?;
    assert_eq!((account.uid, account.gid), (ACCOUNT_UID, ACCOUNT_GID));
    assert_eq!(account.home, PathBuf::from(HOME));
    Ok(())
}


#[test]
fn each_refusal_is_named() -> TestResult {
    assert!(matches!(
        resolve_account(NAME, absent, no_groups, own_primary, owned_directory),
        Err(AccountError::Missing { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, broken, no_groups, own_primary, owned_directory),
        Err(AccountError::Lookup(_))
    ));
    assert!(matches!(
        resolve_account(NAME, root_uid, no_groups, own_primary, owned_directory),
        Err(AccountError::Privileged { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, root_gid, no_groups, own_primary, owned_directory),
        Err(AccountError::Privileged { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, harmless_group, own_primary, owned_directory),
        Err(AccountError::SupplementaryGroups { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, root_group, own_primary, owned_directory),
        Err(AccountError::SupplementaryGroups { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, groups_down, own_primary, owned_directory),
        Err(AccountError::GroupsUnreadable(_))
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, no_groups, disk_primary, owned_directory),
        Err(AccountError::SharedPrimaryGroup { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, no_groups, members_primary, owned_directory),
        Err(AccountError::SharedPrimaryGroup { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, no_groups, shared_primary, owned_directory),
        Err(AccountError::SharedPrimaryGroup { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, no_groups, absent_primary, owned_directory),
        Err(AccountError::SharedPrimaryGroup { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, no_groups, twin_primary, owned_directory),
        Err(AccountError::SharedPrimaryGroup { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, no_groups, primary_down, owned_directory),
        Err(AccountError::PrimaryGroupUnreadable(_))
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, no_groups, own_primary, unreadable),
        Err(AccountError::HomeUnreadable { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, no_groups, own_primary, owned_file),
        Err(AccountError::HomeInvalid { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, no_groups, own_primary, foreign_directory),
        Err(AccountError::HomeInvalid { .. })
    ));
    let refused = resolve_account(NAME, absent, no_groups, own_primary, owned_directory)
        .err()
        .map(|error| error.to_string());
    assert_eq!(refused, Some(format!("the shell account {NAME} does not exist")));
    Ok(())
}


#[test]
fn the_real_lookup_finds_root_and_refuses_it() -> TestResult {
    let root = lookup_account("root")?;
    assert_eq!(root.map(|found| found.uid), Some(ROOT_UID));
    assert!(lookup_account("ostyr-no-such-account-name")?.is_none());
    assert!(matches!(
        resolve_account("root", lookup_account, lookup_groups, own_primary, stat_home),
        Err(AccountError::Privileged { .. })
    ));
    Ok(())
}


#[test]
fn the_home_is_read_without_following_a_link() -> TestResult {
    let directory = private_tempdir()?;
    let facts = stat_home(directory.path())?;
    assert!(facts.is_directory);
    assert_eq!(facts.owner, owner_of(directory.path())?);
    let link = directory.path().join("link");
    std::os::unix::fs::symlink(directory.path(), &link)?;
    assert!(!stat_home(&link)?.is_directory);
    assert!(stat_home(&directory.path().join("missing")).is_err());
    Ok(())
}


#[test]
fn the_composer_pins_the_store_owner_to_root() -> TestResult {
    let (script, _taken) = hold_script();
    let fakes: Fakes = fakes_with(forbidden_spawn, script)?;
    let hooks = ShellHooks {
        clock: &*fakes.clock,
        dial: &*fakes.dial,
        spawn: &*fakes.spawn,
        attach: &*fakes.attach,
        cleanup: &*fakes.cleanup,
    };
    let env = production_env("agent-1".to_owned(), fakes.directory.path().to_path_buf(), hooks);
    assert_eq!(env.store_owner, ROOT_UID);
    assert_eq!(env.agent_id, "agent-1");
    assert_eq!(env.store_directory, fakes.directory.path());
    Ok(())
}


#[test]
fn a_passwd_file_is_read_line_by_line() -> TestResult {
    let directory = private_tempdir()?;
    let passwd = directory.path().join("passwd");
    std::fs::write(
        &passwd,
        "short\nother:x:5:6::/home/other:/bin/sh\nostyr-shell:x:1001:1002::/home/ostyr-shell:/bin/bash\n",
    )?;
    let found = lookup_in(&passwd, NAME)?;
    assert_eq!(
        found.map(|account| (account.uid, account.gid, account.home)),
        Some((ACCOUNT_UID, ACCOUNT_GID, PathBuf::from(HOME)))
    );
    assert!(lookup_in(&passwd, "nobody-here")?.is_none());
    std::fs::write(&passwd, "ostyr-shell:x:abc:1002::/home/x:/bin/sh\n")?;
    assert!(lookup_in(&passwd, NAME).is_err());
    std::fs::write(&passwd, "ostyr-shell:x:1:2\n")?;
    assert!(lookup_in(&passwd, NAME).is_err());
    assert!(lookup_in(&directory.path().join("missing"), NAME).is_err());
    Ok(())
}


#[test]
fn a_group_file_is_read_line_by_line_and_a_member_is_found_by_exact_name() -> TestResult {
    let directory = private_tempdir()?;
    let group_file = directory.path().join("group");
    std::fs::write(
        &group_file,
        "\nroot:x:0:\ndisk:x:6:alice,ostyr-shell\nshadow:x:42:ostyr-shell2,xostyr-shell\ndocker:x:999:ostyr-shell\nostyr-shell:x:1002:\n",
    )?;
    assert_eq!(groups_in(&group_file, NAME)?, vec!["disk".to_owned(), "docker".to_owned()]);
    assert!(groups_in(&group_file, "nobody-here")?.is_empty());
    std::fs::write(&group_file, "disk:x:6\n")?;
    assert!(groups_in(&group_file, NAME).is_err());
    assert!(groups_in(&directory.path().join("missing"), NAME).is_err());
    assert!(lookup_groups("ostyr-no-such-account-name")?.is_empty());
    Ok(())
}


#[test]
fn the_primary_group_is_read_from_both_files_and_every_malformed_line_refuses() -> TestResult {
    let directory = private_tempdir()?;
    let group_file = directory.path().join("group");
    let passwd = directory.path().join("passwd");
    std::fs::write(&group_file, "\nroot:x:0:\ndisk:x:6:\nostyr-shell:x:1002:\nusers:x:100:bob\n")?;
    std::fs::write(
        &passwd,
        "\nroot:x:0:0::/root:/bin/sh\nostyr-shell:x:1001:1002::/home/ostyr-shell:/bin/bash\nbob:x:1002:100::/home/bob:/bin/sh\n",
    )?;
    let own = primary_in(&group_file, &passwd, NAME, ACCOUNT_GID)?;
    assert_eq!(
        own,
        PrimaryGroup {
            entries: vec![named_group(NAME, false)],
            other_users: 0
        }
    );
    let users = primary_in(&group_file, &passwd, NAME, USERS_GID)?;
    assert_eq!(
        users,
        PrimaryGroup {
            entries: vec![named_group("users", true)],
            other_users: 1
        }
    );
    let disk = primary_in(&group_file, &passwd, NAME, DISK_GID)?;
    assert_eq!(disk.entries, vec![named_group("disk", false)]);
    assert!(primary_in(&group_file, &passwd, NAME, UNKNOWN_GID)?.entries.is_empty());
    let bob_shares = primary_in(&group_file, &passwd, "alice", USERS_GID)?;
    assert_eq!(bob_shares.other_users, 1);
    assert!(primary_in(&directory.path().join("missing"), &passwd, NAME, 1).is_err());
    assert!(primary_in(&group_file, &directory.path().join("missing"), NAME, 1).is_err());
    let nowhere = lookup_primary("ostyr-no-such-account-name", UNUSED_GID)?;
    assert_eq!(
        nowhere,
        PrimaryGroup {
            entries: Vec::new(),
            other_users: 0
        }
    );
    ["disk:x:6\n", "disk:x:six:\n", "disk:x\n", "\nroot:x:0:\n:"].iter().try_for_each(|bad| {
        std::fs::write(&group_file, bad)?;
        assert!(primary_in(&group_file, &passwd, NAME, DISK_GID).is_err(), "{bad}");
        Ok::<(), std::io::Error>(())
    })?;
    std::fs::write(&group_file, "disk:x:6:\n")?;
    ["ostyr-shell:x:1:abc\n", "ostyr-shell:x:1\n", "ostyr-shell:x:1:2\nshort"]
        .iter()
        .try_for_each(|bad| {
            std::fs::write(&passwd, bad)?;
            assert!(primary_in(&group_file, &passwd, NAME, DISK_GID).is_err(), "{bad}");
            Ok::<(), std::io::Error>(())
        })?;
    Ok(())
}
