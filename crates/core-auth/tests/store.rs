#[path = "support/failing_writer.rs"]
mod failing_writer;
#[path = "support/types.rs"]
mod types;


#[cfg(unix)]
use core_audit::error::AuditError;
use core_auth::error::AuthError;
use core_auth::model::{Account, TotpEnrolment};
use core_auth::random::os_random;
use core_auth::store::{
    load_accounts, load_accounts_file, lock_path, read_store_locked, save_accounts, save_store_file, update_store_file, STORE_VERSION,
};
use core_auth::types::{AccountMap, CredentialMap};
use failing_writer::FailingWriter;
use std::fs;
#[cfg(unix)]
use std::fs::Permissions;
#[cfg(unix)]
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use tempfile::tempdir;
use types::TestResult;


#[cfg(unix)]
const OWNER_ONLY: u32 = 0o600;


const PATTERN_BYTE: u8 = 7;


const ACCOUNTS_AFTER_UPDATE: usize = 2;


const WRITERS: usize = 6;


const UPDATES_PER_WRITER: usize = 8;


const FILES_AFTER_TWO_SAVES: usize = 2;


#[cfg(unix)]
const LOOSE: u32 = 0o644;


#[cfg(unix)]
const MODE_MASK: u32 = 0o777;


fn sample() -> AccountMap {
    let account = Account {
        username: "alice".to_owned(),
        password_hash: "$argon2id$hash".to_owned(),
        roles: ["reader".to_owned()].into(),
        totp: Some(TotpEnrolment {
            encrypted_secret: "sealed".to_owned(),
            last_step: 1,
            backup_code_hashes: vec!["h1".to_owned()],
        }),
    };
    [("alice".to_owned(), account)].into()
}


#[test]
fn accounts_round_trip() -> TestResult {
    let mut bytes = Vec::new();
    save_accounts(&mut bytes, &sample())?;
    assert!(String::from_utf8(bytes.clone())?.contains("\"version\": 2"));
    assert_eq!(load_accounts(bytes.as_slice())?, sample());
    Ok(())
}


#[test]
fn unsupported_version_and_garbage_are_refused() -> TestResult {
    let future = format!("{{\"version\":{},\"accounts\":[]}}", STORE_VERSION + 1);
    assert!(matches!(load_accounts(future.as_bytes()), Err(AuthError::UnsupportedVersion { found }) if found == STORE_VERSION + 1));
    assert!(matches!(load_accounts("nope".as_bytes()), Err(AuthError::Format(_))));
    assert!(matches!(
        load_accounts("{\"version\":1,\"accounts\":[],\"x\":1}".as_bytes()),
        Err(AuthError::Format(_))
    ));
    Ok(())
}


#[test]
fn write_failures_are_reported() -> TestResult {
    let write_fails = FailingWriter {
        fail_write: true,
        fail_flush: false,
    };
    let flush_fails = FailingWriter {
        fail_write: false,
        fail_flush: true,
    };
    assert!(matches!(save_accounts(write_fails, &sample()), Err(AuthError::Format(_))));
    assert!(matches!(save_accounts(flush_fails, &sample()), Err(AuthError::Io(_))));
    Ok(())
}


#[test]
fn newline_write_failure_is_reported() -> TestResult {
    let mut buffer = [u8::MIN; 0];
    assert!(matches!(
        save_accounts(buffer.as_mut_slice(), &sample()),
        Err(AuthError::Format(_) | AuthError::Io(_))
    ));
    Ok(())
}


#[test]
#[cfg(unix)]
fn store_file_is_created_with_mode_0600() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    save_store_file(&path, &sample(), &CredentialMap::new(), os_random)?;
    assert_eq!(fs::metadata(&path)?.permissions().mode() & MODE_MASK, OWNER_ONLY);
    assert_eq!(load_accounts_file(&path)?, sample());
    assert!(!directory.path().join("accounts.tmp").exists());
    Ok(())
}


#[test]
fn saving_again_replaces_the_file() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    save_store_file(&path, &sample(), &CredentialMap::new(), os_random)?;
    save_store_file(&path, &AccountMap::new(), &CredentialMap::new(), os_random)?;
    assert!(load_accounts_file(&path)?.is_empty());
    Ok(())
}


#[test]
fn missing_file_is_an_empty_store() -> TestResult {
    let directory = tempdir()?;
    assert!(load_accounts_file(&directory.path().join("absent.json"))?.is_empty());
    Ok(())
}


#[test]
#[cfg(unix)]
fn loose_modes_are_refused() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    save_store_file(&path, &sample(), &CredentialMap::new(), os_random)?;
    fs::set_permissions(&path, Permissions::from_mode(LOOSE))?;
    assert!(matches!(
        load_accounts_file(&path),
        Err(AuthError::Audit(AuditError::InsecurePermissions { .. }))
    ));
    Ok(())
}


fn constant_random(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    buffer.fill(PATTERN_BYTE);
    Ok(())
}


fn failing_random(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


#[test]
fn an_existing_temporary_file_is_never_reused() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    let temporary = directory.path().join(".accounts.json.0707070707070707.tmp");
    fs::write(&temporary, "keep")?;
    assert!(matches!(
        save_store_file(&path, &sample(), &CredentialMap::new(), constant_random),
        Err(AuthError::Io(error)) if error.kind() == std::io::ErrorKind::AlreadyExists
    ));
    assert_eq!(fs::read_to_string(&temporary)?, "keep");
    assert!(!path.exists());
    Ok(())
}


#[test]
#[cfg(unix)]
fn a_symlinked_temporary_name_is_not_followed() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    let victim = directory.path().join("victim");
    fs::write(&victim, "precious")?;
    symlink(&victim, directory.path().join(".accounts.json.0707070707070707.tmp"))?;
    assert!(matches!(
        save_store_file(&path, &sample(), &CredentialMap::new(), constant_random),
        Err(AuthError::Io(_))
    ));
    assert_eq!(fs::read_to_string(&victim)?, "precious");
    Ok(())
}


#[test]
fn different_store_names_never_share_a_temporary_file() -> TestResult {
    let directory = tempdir()?;
    let first = directory.path().join("accounts.json");
    let second = directory.path().join("accounts.bak");
    save_store_file(&first, &sample(), &CredentialMap::new(), constant_random)?;
    save_store_file(&second, &AccountMap::new(), &CredentialMap::new(), constant_random)?;
    assert_eq!(load_accounts_file(&first)?, sample());
    assert!(load_accounts_file(&second)?.is_empty());
    assert_eq!(fs::read_dir(directory.path())?.count(), FILES_AFTER_TWO_SAVES);
    Ok(())
}


#[test]
fn random_failure_and_nameless_paths_are_reported() -> TestResult {
    assert!(matches!(
        save_store_file(Path::new("accounts.json"), &sample(), &CredentialMap::new(), failing_random),
        Err(AuthError::Random(_))
    ));
    assert!(matches!(
        save_store_file(Path::new("/"), &sample(), &CredentialMap::new(), os_random),
        Err(AuthError::Usage(_))
    ));
    Ok(())
}


#[test]
fn io_failures_are_reported() -> TestResult {
    let directory = tempdir()?;
    let blocker = directory.path().join("blocker");
    fs::write(&blocker, "")?;
    assert!(matches!(load_accounts_file(&blocker.join("child")), Err(AuthError::Io(_))));
    assert!(matches!(
        save_store_file(
            &directory.path().join("missing").join("a.json"),
            &sample(),
            &CredentialMap::new(),
            os_random
        ),
        Err(AuthError::Io(_))
    ));
    let target = directory.path().join("target");
    fs::create_dir(&target)?;
    fs::write(target.join("child"), "")?;
    assert!(matches!(
        save_store_file(&target, &sample(), &CredentialMap::new(), os_random),
        Err(AuthError::Io(_))
    ));
    Ok(())
}


#[test]
fn malformed_file_is_reported() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    fs::write(&path, "oops")?;
    #[cfg(unix)]
    fs::set_permissions(&path, Permissions::from_mode(OWNER_ONLY))?;
    assert!(matches!(load_accounts_file(&path), Err(AuthError::Format(_))));
    Ok(())
}


fn named_account(name: &str) -> Account {
    Account {
        username: name.to_owned(),
        password_hash: "$argon2id$hash".to_owned(),
        roles: ["reader".to_owned()].into(),
        totp: None,
    }
}


#[test]
fn an_update_rereads_the_file_and_applies_only_its_mutation() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    save_store_file(&path, &sample(), &CredentialMap::new(), os_random)?;
    update_store_file(&path, os_random, |accounts, _| {
        accounts.insert("bob".to_owned(), named_account("bob"));
        Ok(())
    })?
    .saved?;
    let stale = update_store_file(&path, os_random, |accounts, _| Ok(accounts.keys().cloned().collect::<Vec<_>>()))?;
    assert_eq!(stale.value, ["alice", "bob"]);
    assert_eq!(load_accounts_file(&path)?.len(), ACCOUNTS_AFTER_UPDATE);
    assert!(lock_path(&path).ends_with("accounts.json.lock"));
    assert_eq!(read_store_locked(&path)?.0.len(), ACCOUNTS_AFTER_UPDATE);
    Ok(())
}


#[test]
fn a_failing_mutation_or_read_writes_nothing() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    save_store_file(&path, &sample(), &CredentialMap::new(), os_random)?;
    let before = fs::read(&path)?;
    let refused = update_store_file(&path, os_random, |accounts, _| {
        accounts.clear();
        Err::<(), _>(AuthError::Usage("refused".to_owned()))
    });
    assert!(matches!(refused, Err(AuthError::Usage(_))));
    assert_eq!(fs::read(&path)?, before);
    let broken = directory.path().join("broken.json");
    fs::write(&broken, "not json")?;
    #[cfg(unix)]
    fs::set_permissions(&broken, Permissions::from_mode(OWNER_ONLY))?;
    assert!(matches!(update_store_file(&broken, os_random, |_, _| Ok(())), Err(AuthError::Format(_))));
    assert!(matches!(read_store_locked(&broken), Err(AuthError::Format(_))));
    assert!(matches!(
        read_store_locked(&directory.path().join("absent").join("accounts.json")),
        Err(AuthError::Io(_))
    ));
    Ok(())
}


#[test]
fn a_failed_write_is_reported_beside_the_value() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    let updated = update_store_file(&path, failing_random, |_, _| Ok(PATTERN_BYTE))?;
    assert_eq!(updated.value, PATTERN_BYTE);
    assert!(matches!(updated.saved, Err(AuthError::Random(_))));
    assert!(!path.exists());
    Ok(())
}


#[test]
fn concurrent_writers_never_lose_an_update() -> TestResult {
    let directory = tempdir()?;
    let path = directory.path().join("accounts.json");
    let workers: Vec<_> = (0..WRITERS)
        .map(|writer| {
            let target = path.clone();
            std::thread::spawn(move || -> Result<(), AuthError> {
                (0..UPDATES_PER_WRITER).try_for_each(|round| {
                    let name = format!("user-{writer}-{round}");
                    update_store_file(&target, os_random, |accounts, _| {
                        accounts.insert(name.clone(), named_account(&name));
                        Ok(())
                    })?
                    .saved
                })
            })
        })
        .collect();
    workers.into_iter().try_for_each(|worker| -> TestResult {
        worker.join().map_err(|_| "writer panicked")??;
        Ok(())
    })?;
    assert_eq!(load_accounts_file(&path)?.len(), WRITERS * UPDATES_PER_WRITER);
    Ok(())
}
