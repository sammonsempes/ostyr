use crate::support::{keys_for, pair_of, routine_key, write_secret, KEY_ID, SEED_BYTE, SEED_LENGTH, START};
use crate::types::KeyChange;
use agent_command::model::{KeyClass, TrustedKeys};
use command_issue::error::{KeyRefusal, PairError};
use command_issue::key::{check_key, decode_seed, load_pair, pair_state, read_seed, swap_pair, Pair};
use command_issue::limits::LIFETIME_SECONDS;
use data_encoding::HEXLOWER;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::sync::Arc;
use tempfile::tempdir;


const OTHER_SEED_BYTE: u8 = 0xab;


const SEED_HEX_LENGTH: usize = 64;


const SEED_TOO_LONG: usize = 67;


const SEED_TOO_SHORT: usize = 63;


const GROUP_READABLE: u32 = 0o640;


const SLACK: u64 = 1;


const SLACK_BYTE: u8 = 3;


pub struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("read failed"))
    }
}


pub fn seed_hex(byte: u8) -> String {
    HEXLOWER.encode(&[byte; SEED_LENGTH])
}


pub fn chain(error: &dyn Error) -> String {
    std::iter::successors(Some(error), |current: &&dyn Error| (*current).source())
        .map(|link| format!("{link} {link:?}"))
        .collect::<Vec<String>>()
        .join(" | ")
}


pub fn seed_file(dir: &Path, name: &str, text: &str) -> Result<std::path::PathBuf, Box<dyn Error>> {
    let path = dir.join(name);
    write_secret(&path, text.as_bytes())?;
    Ok(path)
}


fn keys_with(change: impl Fn(&mut agent_command::model::TrustedKey)) -> (Pair, TrustedKeys) {
    let pair = pair_of(SEED_BYTE, KEY_ID);
    let mut key = routine_key(pair.public_key);
    change(&mut key);
    (
        pair,
        TrustedKeys {
            keys: BTreeMap::from([(KEY_ID.to_owned(), key)]),
        },
    )
}


#[test]
fn the_scoped_routine_key_is_accepted() -> Result<(), Box<dyn Error>> {
    let pair = pair_of(SEED_BYTE, KEY_ID);
    check_key(&keys_for(&pair), &pair, START)?;
    Ok(())
}


#[test]
fn every_key_refusal_is_named() -> Result<(), Box<dyn Error>> {
    let scope = |names: &[&str]| Some(names.iter().map(|name| (*name).to_owned()).collect::<BTreeSet<String>>());
    let other_pair = pair_of(OTHER_SEED_BYTE, KEY_ID);
    let cases: Vec<(KeyRefusal, KeyChange)> = vec![
        (KeyRefusal::WrongClass, Box::new(|key| key.class = KeyClass::Sensitive)),
        (KeyRefusal::WrongScope, Box::new(|key| key.actions = None)),
        (
            KeyRefusal::WrongScope,
            Box::new(move |key| key.actions = scope(&["ping", "collect_status", "isolate"])),
        ),
        (KeyRefusal::WrongScope, Box::new(move |key| key.actions = scope(&["ping"]))),
        (KeyRefusal::Revoked, Box::new(|key| key.revoked = true)),
        (KeyRefusal::NotYetValid, Box::new(|key| key.not_before = START + SLACK)),
        (
            KeyRefusal::ExpiresTooSoon,
            Box::new(|key| key.not_after = START + LIFETIME_SECONDS - SLACK),
        ),
        (KeyRefusal::PublicKeyMismatch, Box::new(move |key| key.public_key = other_pair.public_key)),
    ];
    cases.iter().try_for_each(|(expected, change)| {
        let (pair, keys) = keys_with(change);
        let refusal = check_key(&keys, &pair, START).err().ok_or("accepted")?;
        assert_eq!(&refusal, expected);
        assert!(!refusal.to_string().is_empty());
        Ok::<(), Box<dyn Error>>(())
    })?;
    let pair = pair_of(SEED_BYTE, "unknown");
    assert_eq!(
        check_key(&keys_for(&pair_of(SEED_BYTE, KEY_ID)), &pair, START),
        Err(KeyRefusal::UnknownKey)
    );
    let (pair_last, keys_last) = keys_with(|key| key.not_after = START + LIFETIME_SECONDS);
    check_key(&keys_last, &pair_last, START)?;
    assert_eq!(check_key(&keys_last, &pair_last, u64::MAX), Err(KeyRefusal::ExpiresTooSoon));
    Ok(())
}


#[test]
fn the_seed_is_read_with_or_without_a_final_newline() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let with_newline = seed_file(dir.path(), "a.seed", &format!("{}\n", seed_hex(SEED_BYTE)))?;
    let without = seed_file(dir.path(), "b.seed", &seed_hex(SEED_BYTE))?;
    assert_eq!(read_seed(&with_newline)?.as_slice(), &[SEED_BYTE; SEED_LENGTH]);
    assert_eq!(read_seed(&without)?.as_slice(), &[SEED_BYTE; SEED_LENGTH]);
    Ok(())
}


#[test]
fn a_malformed_seed_is_refused_with_one_fixed_text() -> Result<(), Box<dyn Error>> {
    let marker = seed_hex(OTHER_SEED_BYTE);
    let bad = [
        marker.to_uppercase(),
        format!("{marker}0"),
        format!("{marker}\n\n"),
        format!("{marker}\r\n"),
        marker.chars().take(SEED_TOO_SHORT).collect::<String>(),
        "0".repeat(SEED_TOO_LONG),
        "0".repeat(SEED_HEX_LENGTH + SEED_HEX_LENGTH),
        String::new(),
        format!("{}g", marker.chars().take(SEED_TOO_SHORT).collect::<String>()),
    ];
    bad.iter().try_for_each(|text| {
        let error = decode_seed(&mut text.as_bytes()).err().ok_or("accepted")?;
        assert!(matches!(error, PairError::Format), "{error}");
        let shown = chain(&error);
        assert!(!shown.contains(&marker) && !shown.contains(&marker.to_uppercase()), "{shown}");
        assert!(shown.contains("commands.routine_seed_file"));
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn a_failing_read_is_a_named_error() -> Result<(), Box<dyn Error>> {
    let error = decode_seed(&mut Broken).err().ok_or("accepted")?;
    assert!(matches!(error, PairError::Read(_)), "{error}");
    assert!(chain(&error).contains("commands.routine_seed_file"));
    Ok(())
}


#[test]
fn a_seed_file_the_service_may_not_trust_is_refused_before_reading() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let readable = seed_file(dir.path(), "group.seed", &seed_hex(SEED_BYTE))?;
    fs::set_permissions(&readable, fs::Permissions::from_mode(GROUP_READABLE))?;
    let link = dir.path().join("link.seed");
    symlink(&readable, &link)?;
    let directory = dir.path().join("dir.seed");
    fs::create_dir(&directory)?;
    [readable, link, directory, dir.path().join("missing.seed")].iter().try_for_each(|path| {
        let error = read_seed(path).err().ok_or("accepted")?;
        assert!(matches!(error, PairError::Open(_)), "{error}");
        assert!(!chain(&error).contains(&seed_hex(SEED_BYTE)));
        Ok::<(), Box<dyn Error>>(())
    })
}


#[test]
fn the_pair_loads_only_when_the_key_checks_pass_and_never_prints_the_seed() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let path = seed_file(dir.path(), "ok.seed", &format!("{}\n", seed_hex(SEED_BYTE)))?;
    let pair = pair_of(SEED_BYTE, KEY_ID);
    let loaded = load_pair(&path, KEY_ID, &keys_for(&pair), START)?;
    assert_eq!(loaded.public_key, pair.public_key);
    let shown = format!("{loaded:?} {:?}", pair_state(&loaded));
    assert!(!shown.contains(&seed_hex(SEED_BYTE)), "{shown}");
    let missing = load_pair(&dir.path().join("absent.seed"), KEY_ID, &keys_for(&pair), START)
        .err()
        .ok_or("loaded")?;
    assert!(matches!(missing, PairError::Open(_)), "{missing}");
    let (_, revoked) = keys_with(|key| key.revoked = true);
    let error = load_pair(&path, KEY_ID, &revoked, START).err().ok_or("accepted")?;
    assert!(matches!(error, PairError::Key(KeyRefusal::Revoked)), "{error}");
    assert!(chain(&error).contains("commands.key_id"));
    Ok(())
}


#[test]
fn the_state_lists_the_key_id_and_the_public_key_only() -> Result<(), Box<dyn Error>> {
    let pair = pair_of(SEED_BYTE, KEY_ID);
    let state = pair_state(&pair);
    assert_eq!(
        state,
        vec![
            ("commands.key_id".to_owned(), KEY_ID.to_owned()),
            ("commands.public_key".to_owned(), HEXLOWER.encode(&pair.public_key.to_bytes())),
        ]
    );
    Ok(())
}


#[test]
fn a_valid_swap_signs_with_the_new_key_and_a_refused_swap_keeps_the_old_one() -> Result<(), Box<dyn Error>> {
    let dir = tempdir()?;
    let old = pair_of(SEED_BYTE, KEY_ID);
    let new = pair_of(OTHER_SEED_BYTE, "routine-2");
    let holder = arc_swap::ArcSwap::from_pointee(old.clone());
    let both = TrustedKeys {
        keys: BTreeMap::from([
            (KEY_ID.to_owned(), routine_key(old.public_key)),
            ("routine-2".to_owned(), routine_key(new.public_key)),
        ]),
    };
    let new_seed = seed_file(dir.path(), "new.seed", &seed_hex(OTHER_SEED_BYTE))?;
    let wrong_seed = seed_file(dir.path(), "wrong.seed", &seed_hex(SEED_BYTE + SLACK_BYTE))?;
    let refused = swap_pair(&holder, &wrong_seed, "routine-2", &both, START).err().ok_or("swapped")?;
    assert!(matches!(refused, PairError::Key(KeyRefusal::PublicKeyMismatch)), "{refused}");
    assert_eq!(holder.load().public_key, old.public_key);
    swap_pair(&holder, &new_seed, "routine-2", &both, START)?;
    let current: Arc<Pair> = holder.load_full();
    assert_eq!(current.public_key, new.public_key);
    assert_eq!(current.key_id, "routine-2");
    Ok(())
}
