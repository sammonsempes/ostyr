use crate::support::{fakes_with, forbidden_spawn, hold_script, owner_of, private_tempdir, Fakes};
use crate::types::TestResult;
use agent_shell::account::{lookup_account, lookup_in, resolve_account, stat_home, AccountEntry, HomeFacts};
use agent_shell::compose::production_env;
use agent_shell::error::AccountError;
use agent_shell::model::{ShellHooks, ROOT_UID};
use std::io;
use std::path::{Path, PathBuf};


const ACCOUNT_UID: u32 = 1001;


const ACCOUNT_GID: u32 = 1002;


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
    let account = resolve_account(NAME, good_entry, owned_directory)?;
    assert_eq!((account.uid, account.gid), (ACCOUNT_UID, ACCOUNT_GID));
    assert_eq!(account.home, PathBuf::from(HOME));
    Ok(())
}


#[test]
fn each_refusal_is_named() -> TestResult {
    assert!(matches!(
        resolve_account(NAME, absent, owned_directory),
        Err(AccountError::Missing { .. })
    ));
    assert!(matches!(resolve_account(NAME, broken, owned_directory), Err(AccountError::Lookup(_))));
    assert!(matches!(
        resolve_account(NAME, root_uid, owned_directory),
        Err(AccountError::Privileged { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, root_gid, owned_directory),
        Err(AccountError::Privileged { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, unreadable),
        Err(AccountError::HomeUnreadable { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, owned_file),
        Err(AccountError::HomeInvalid { .. })
    ));
    assert!(matches!(
        resolve_account(NAME, good_entry, foreign_directory),
        Err(AccountError::HomeInvalid { .. })
    ));
    let refused = resolve_account(NAME, absent, owned_directory).err().map(|error| error.to_string());
    assert_eq!(refused, Some(format!("the shell account {NAME} does not exist")));
    Ok(())
}


#[test]
fn the_real_lookup_finds_root_and_refuses_it() -> TestResult {
    let root = lookup_account("root")?;
    assert_eq!(root.map(|found| found.uid), Some(ROOT_UID));
    assert!(lookup_account("ostyr-no-such-account-name")?.is_none());
    assert!(matches!(
        resolve_account("root", lookup_account, stat_home),
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
