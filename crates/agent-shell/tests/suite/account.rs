use crate::support::{fakes_with, forbidden_spawn, hold_script, owner_of, private_tempdir, Fakes};
use crate::types::TestResult;
use agent_shell::account::{
    groups_in, holds_uid, judge_uid, lookup_in, primary_in, read_database, read_databases, read_databases_at, resolve_account, resolve_in, stat_home,
    uid_holders, Databases, GroupEntry, HomeFacts, PrimaryGroup, MAX_DATABASE_BYTES,
};
use agent_shell::compose::production_shared;
use agent_shell::error::AccountError;
use agent_shell::model::{SharedHooks, ROOT_UID};
use std::io;
use std::path::{Path, PathBuf};


const ACCOUNT_UID: u32 = 1001;


const ACCOUNT_GID: u32 = 1002;


const DISK_GID: u32 = 6;


const USERS_GID: u32 = 100;


const UNKNOWN_GID: u32 = 77;


const HOLDER_UID: u32 = 5;


const TWO_HOLDERS: usize = 2;


const NAME: &str = "ostyr-shell";


const HOME: &str = "/home/ostyr-shell";


const THIRD: usize = 2;


const GOOD_PASSWD: &str = "root:x:0:0::/root:/bin/sh\nostyr-shell:x:1001:1002::/home/ostyr-shell:/bin/bash\n";


const GOOD_GROUP: &str = "root:x:0:\nostyr-shell:x:1002:\n";


fn named_group(name: &str, has_members: bool) -> GroupEntry {
    GroupEntry {
        name: name.to_owned(),
        has_members,
    }
}


fn databases(passwd: &str, group: &str) -> Databases {
    Databases {
        passwd: passwd.to_owned(),
        group: group.to_owned(),
    }
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


fn good_databases() -> io::Result<Databases> {
    Ok(databases(GOOD_PASSWD, GOOD_GROUP))
}


fn broken_databases() -> io::Result<Databases> {
    Err(io::Error::other("database down"))
}


fn refusal(passwd: &str, group: &str) -> Option<AccountError> {
    resolve_in(NAME, &databases(passwd, group), owned_directory).err()
}


#[test]
fn the_account_is_resolved_once_with_its_ids_and_home() -> TestResult {
    let account = resolve_account(NAME, good_databases, owned_directory)?;
    assert_eq!((account.uid, account.gid), (ACCOUNT_UID, ACCOUNT_GID));
    assert_eq!(account.home, PathBuf::from(HOME));
    assert!(matches!(
        resolve_account(NAME, broken_databases, owned_directory),
        Err(AccountError::Lookup(_))
    ));
    Ok(())
}


#[test]
fn each_refusal_is_named() -> TestResult {
    assert!(matches!(refusal("", GOOD_GROUP), Some(AccountError::Missing { .. })));
    assert!(matches!(
        refusal("ostyr-shell:x:abc:1002::/h:/b\n", GOOD_GROUP),
        Some(AccountError::Lookup(_))
    ));
    assert!(matches!(
        refusal("ostyr-shell:x:0:1002::/h:/b\n", GOOD_GROUP),
        Some(AccountError::Privileged { .. })
    ));
    assert!(matches!(
        refusal("ostyr-shell:x:1001:0::/h:/b\n", GOOD_GROUP),
        Some(AccountError::Privileged { .. })
    ));
    assert!(matches!(
        refusal(GOOD_PASSWD, "users:x:100:ostyr-shell\nostyr-shell:x:1002:\n"),
        Some(AccountError::SupplementaryGroups { .. })
    ));
    assert!(matches!(refusal(GOOD_PASSWD, "disk:x:6\n"), Some(AccountError::GroupsUnreadable(_))));
    assert!(matches!(
        refusal(GOOD_PASSWD, "disk:x:1002:\n"),
        Some(AccountError::SharedPrimaryGroup { .. })
    ));
    assert!(matches!(
        refusal(GOOD_PASSWD, "ostyr-shell:x:1002:bob\n"),
        Some(AccountError::SharedPrimaryGroup { .. })
    ));
    assert!(matches!(
        refusal(&format!("{GOOD_PASSWD}bob:x:1002:1002::/home/bob:/bin/sh\n"), GOOD_GROUP),
        Some(AccountError::SharedPrimaryGroup { .. })
    ));
    assert!(matches!(
        refusal(GOOD_PASSWD, "root:x:0:\n"),
        Some(AccountError::SharedPrimaryGroup { .. })
    ));
    assert!(matches!(
        refusal(GOOD_PASSWD, "ostyr-shell:x:1002:\nostyr-shell:x:1002:\n"),
        Some(AccountError::SharedPrimaryGroup { .. })
    ));
    assert!(matches!(
        refusal(&format!("{GOOD_PASSWD}short\n"), GOOD_GROUP),
        Some(AccountError::PrimaryGroupUnreadable(_))
    ));
    let home_refusals = [unreadable, owned_file, foreign_directory].map(|home| resolve_in(NAME, &databases(GOOD_PASSWD, GOOD_GROUP), home).err());
    assert!(matches!(home_refusals.first(), Some(Some(AccountError::HomeUnreadable { .. }))));
    assert!(matches!(home_refusals.get(1), Some(Some(AccountError::HomeInvalid { .. }))));
    assert!(matches!(home_refusals.get(THIRD), Some(Some(AccountError::HomeInvalid { .. }))));
    assert_eq!(
        refusal("", GOOD_GROUP).map(|error| error.to_string()),
        Some(format!("the shell account {NAME} does not exist"))
    );
    Ok(())
}


#[test]
fn the_real_databases_find_root_and_refuse_it() -> TestResult {
    let read = read_databases()?;
    assert_eq!(lookup_in(&read.passwd, "root")?.map(|found| found.uid), Some(ROOT_UID));
    assert!(lookup_in(&read.passwd, "ostyr-no-such-account-name")?.is_none());
    assert!(groups_in(&read.group, "ostyr-no-such-account-name")?.is_empty());
    assert!(matches!(
        resolve_account("root", read_databases, stat_home),
        Err(AccountError::Privileged { .. })
    ));
    Ok(())
}


#[test]
fn each_file_is_read_once_and_a_missing_one_is_an_error() -> TestResult {
    let directory = private_tempdir()?;
    let passwd = directory.path().join("passwd");
    let group_file = directory.path().join("group");
    std::fs::write(&passwd, "p")?;
    std::fs::write(&group_file, "g")?;
    assert_eq!(read_databases_at(&passwd, &group_file)?, databases("p", "g"));
    assert!(read_databases_at(&directory.path().join("missing"), &group_file).is_err());
    assert!(read_databases_at(&passwd, &directory.path().join("missing")).is_err());
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
    let hooks = SharedHooks {
        clock: &*fakes.clock,
        dial: &*fakes.dial,
        attach: &*fakes.attach,
        enabled: &|| true,
    };
    let env = production_shared("agent-1".to_owned(), fakes.directory.path().to_path_buf(), hooks);
    assert_eq!(env.store_owner, ROOT_UID);
    assert_eq!(env.agent_id, "agent-1");
    assert_eq!(env.store_directory, fakes.directory.path());
    Ok(())
}


#[test]
fn a_passwd_text_is_read_line_by_line() -> TestResult {
    let text = "short\nother:x:5:6::/home/other:/bin/sh\nostyr-shell:x:1001:1002::/home/ostyr-shell:/bin/bash\n";
    let found = lookup_in(text, NAME)?;
    assert_eq!(
        found.map(|account| (account.uid, account.gid, account.home)),
        Some((ACCOUNT_UID, ACCOUNT_GID, PathBuf::from(HOME)))
    );
    assert!(lookup_in(text, "nobody-here")?.is_none());
    assert!(lookup_in("ostyr-shell:x:abc:1002::/home/x:/bin/sh\n", NAME).is_err());
    assert!(lookup_in("ostyr-shell:x:1:2\n", NAME).is_err());
    Ok(())
}


#[test]
fn a_group_text_is_read_line_by_line_and_a_member_is_found_by_exact_name() -> TestResult {
    let text = "\nroot:x:0:\ndisk:x:6:alice,ostyr-shell\nshadow:x:42:ostyr-shell2,xostyr-shell\ndocker:x:999:ostyr-shell\nostyr-shell:x:1002:\n";
    assert_eq!(groups_in(text, NAME)?, vec!["disk".to_owned(), "docker".to_owned()]);
    assert!(groups_in(text, "nobody-here")?.is_empty());
    assert!(groups_in("disk:x:6\n", NAME).is_err());
    Ok(())
}


#[test]
fn the_primary_group_is_read_from_both_texts_and_every_malformed_line_refuses() -> TestResult {
    let group_text = "\nroot:x:0:\ndisk:x:6:\nostyr-shell:x:1002:\nusers:x:100:bob\n";
    let passwd = "\nroot:x:0:0::/root:/bin/sh\nostyr-shell:x:1001:1002::/home/ostyr-shell:/bin/bash\nbob:x:1002:100::/home/bob:/bin/sh\n";
    assert_eq!(
        primary_in(group_text, passwd, NAME, ACCOUNT_GID)?,
        PrimaryGroup {
            entries: vec![named_group(NAME, false)],
            other_users: 0
        }
    );
    assert_eq!(
        primary_in(group_text, passwd, NAME, USERS_GID)?,
        PrimaryGroup {
            entries: vec![named_group("users", true)],
            other_users: 1
        }
    );
    assert_eq!(primary_in(group_text, passwd, NAME, DISK_GID)?.entries, vec![named_group("disk", false)]);
    assert!(primary_in(group_text, passwd, NAME, UNKNOWN_GID)?.entries.is_empty());
    assert_eq!(primary_in(group_text, passwd, "alice", USERS_GID)?.other_users, 1);
    ["disk:x:6\n", "disk:x:six:\n", "disk:x\n", "\nroot:x:0:\n:"].iter().try_for_each(|bad| {
        if primary_in(bad, passwd, NAME, DISK_GID).is_err() {
            Ok(())
        } else {
            Err(format!("accepted {bad}"))
        }
    })?;
    ["ostyr-shell:x:1:abc\n", "ostyr-shell:x:1\n", "ostyr-shell:x:1:2\nshort"]
        .iter()
        .try_for_each(|bad| {
            if primary_in("disk:x:6:\n", bad, NAME, DISK_GID).is_err() {
                Ok(())
            } else {
                Err(format!("accepted {bad}"))
            }
        })?;
    Ok(())
}


#[test]
fn a_database_over_the_cap_is_refused_by_name() -> TestResult {
    let directory = private_tempdir()?;
    let path = directory.path().join("passwd");
    let file = std::fs::File::create(&path)?;
    file.set_len(MAX_DATABASE_BYTES)?;
    assert_eq!(read_database(&path)?.len(), usize::try_from(MAX_DATABASE_BYTES)?);
    file.set_len(MAX_DATABASE_BYTES + 1)?;
    let refusal = read_database(&path).err().ok_or("accepted")?;
    assert_eq!(refusal.kind(), std::io::ErrorKind::InvalidData);
    assert_eq!(refusal.to_string(), "the account database is larger than its limit");
    assert!(read_databases_at(&path, &path).is_err());
    Ok(())
}


#[test]
fn a_uid_held_by_another_passwd_line_is_refused_by_name() -> TestResult {
    let ordinary_user = format!("{GOOD_PASSWD}bob:x:1001:1500::/home/bob:/bin/sh\n");
    assert!(matches!(refusal(&ordinary_user, GOOD_GROUP), Some(AccountError::SharedUid { .. })));
    let alias = format!("{GOOD_PASSWD}ostyr-alias:x:1001:1500::/home/ostyr-shell:/bin/sh\n");
    assert!(matches!(refusal(&alias, GOOD_GROUP), Some(AccountError::SharedUid { .. })));
    let twin = format!("{GOOD_PASSWD}ostyr-shell:x:1001:1002::/home/ostyr-shell:/bin/bash\n");
    assert!(matches!(refusal(&twin, GOOD_GROUP), Some(AccountError::SharedUid { .. })));
    let broken = format!("{GOOD_PASSWD}bob:x:abc:1500::/home/bob:/bin/sh\n");
    assert!(matches!(refusal(&broken, GOOD_GROUP), Some(AccountError::Lookup(_))));
    assert!(refusal(GOOD_PASSWD, GOOD_GROUP).is_none());
    assert_eq!(
        refusal(&ordinary_user, GOOD_GROUP).map(|error| error.to_string()),
        Some(format!("the uid of the shell account {NAME} is held by another passwd line"))
    );
    Ok(())
}


#[test]
fn the_uid_holders_are_counted_line_by_line() -> TestResult {
    assert_eq!(uid_holders(GOOD_PASSWD, ACCOUNT_UID)?, 1);
    assert_eq!(uid_holders("a:x:5:1::/h:/s\n\nb:x:5:1::/h:/s\n", HOLDER_UID)?, TWO_HOLDERS);
    assert_eq!(uid_holders("", HOLDER_UID)?, 0);
    assert!(holds_uid("", HOLDER_UID).is_ok_and(|held| !held));
    assert!(holds_uid("a:x:5", HOLDER_UID).is_ok_and(|held| held));
    assert!(holds_uid("a:x", HOLDER_UID).is_err());
    assert!(holds_uid("a:x:five:1", HOLDER_UID).is_err());
    assert!(uid_holders("a:x:5:1\nshort\n", HOLDER_UID).is_err());
    assert!(judge_uid(NAME, 1).is_ok());
    assert!(matches!(judge_uid(NAME, 0), Err(AccountError::SharedUid { .. })));
    assert!(matches!(judge_uid(NAME, TWO_HOLDERS), Err(AccountError::SharedUid { .. })));
    Ok(())
}
