#![cfg(unix)]

#[path = "support/types.rs"]
mod types;


use serde_json::Value;
use site_collector::dirfs::open_directory;
use site_collector::epoch::{load_epoch, new_epoch, valid_epoch};
use site_collector::forward::{forward_once, read_cursor, write_cursor};
use site_collector::forward_model::{ForwardLimits, CURSOR_FILE, EPOCH_FILE};
use site_collector::spool::{append, open_spool, spool_stats, sync_from};
use site_collector::spool_model::{Priority, SpoolConfig, MAX_FRAME_BYTES};
use site_collector::types::DirHandle;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;
use time::OffsetDateTime;
use types::TestResult;


const NOW_SECONDS: i64 = 1_800_000_000;


const FRAMES_IN_TOTAL: u64 = 3;


const MANY: usize = 100;


const ONE_MIB: u64 = 1 << 20;


const EPOCH_LENGTH: usize = 32;


const GOOD: &[u8] = b"<34>1 2026-11-10T10:00:00Z router1 sshd - - - hello";


fn config() -> SpoolConfig {
    SpoolConfig {
        segment_max_bytes: MAX_FRAME_BYTES,
        total_max_bytes: MAX_FRAME_BYTES * FRAMES_IN_TOTAL,
    }
}


fn limits() -> ForwardLimits {
    ForwardLimits {
        max_records: MANY,
        agent_spool_max_bytes: ONE_MIB,
    }
}


fn epochs_of(path: &Path) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    fs::read_to_string(path)?
        .lines()
        .map(|line| {
            let event: Value = serde_json::from_str(line)?;
            Ok(event
                .pointer("/labels/collector_epoch")
                .and_then(Value::as_str)
                .ok_or("no epoch")?
                .to_owned())
        })
        .collect()
}


#[test]
fn a_spool_creates_one_epoch_and_keeps_it_across_reopens() -> TestResult {
    let root = TempDir::new()?;
    let first = open_spool(root.path(), config())?;
    assert!(valid_epoch(&first.epoch));
    assert_eq!(first.epoch.len(), EPOCH_LENGTH);
    assert_eq!(fs::read_to_string(root.path().join(EPOCH_FILE))?.trim(), first.epoch);
    let epoch = first.epoch.clone();
    drop(first);
    assert_eq!(open_spool(root.path(), config())?.epoch, epoch);
    Ok(())
}


#[test]
fn a_malformed_epoch_file_is_replaced() -> TestResult {
    let root = TempDir::new()?;
    fs::write(root.path().join(EPOCH_FILE), "not hex")?;
    let spool = open_spool(root.path(), config())?;
    assert!(valid_epoch(&spool.epoch));
    assert!(!valid_epoch(&spool.epoch.to_uppercase()));
    assert!(!valid_epoch("abc"));
    Ok(())
}


#[test]
fn a_spool_truncated_below_the_cursor_starts_a_new_epoch() -> TestResult {
    let root = TempDir::new()?;
    let agent = root.path().join("agent.spool");
    let spool_dir = root.path().join("spool");
    fs::create_dir(&spool_dir)?;
    let now = OffsetDateTime::from_unix_timestamp(NOW_SECONDS)?;
    let mut spool = open_spool(&spool_dir, config())?;
    (0..FRAMES_IN_TOTAL).try_for_each(|_| append(&mut spool, Priority::Low, GOOD).map(|_| ()))?;
    forward_once(&mut spool, &agent, &limits(), now, write_cursor)?;
    let old_epoch = spool.epoch.clone();
    drop(spool);
    fs::read_dir(&spool_dir)?
        .map(|entry| Ok(entry?.path()))
        .collect::<Result<Vec<_>, std::io::Error>>()?
        .iter()
        .filter(|path| path.extension().is_some_and(|extension| extension == "seg"))
        .try_for_each(fs::remove_file)?;
    let mut reopened = open_spool(&spool_dir, config())?;
    assert_ne!(reopened.epoch, old_epoch);
    append(&mut reopened, Priority::Low, GOOD)?;
    let report = forward_once(&mut reopened, &agent, &limits(), now, write_cursor)?;
    assert_eq!(report.forwarded, 1);
    assert_eq!(fs::read_to_string(spool_dir.join(EPOCH_FILE))?.trim(), reopened.epoch);
    let handle = open_directory(&spool_dir)?;
    assert_eq!(read_cursor(&handle)?, 1);
    let epochs = epochs_of(&agent)?;
    assert_eq!(epochs.len(), FRAMES_IN_TOTAL as usize + 1);
    assert_eq!(epochs.last(), Some(&reopened.epoch));
    assert_eq!(epochs.first(), Some(&old_epoch));
    let epoch_after = reopened.epoch.clone();
    forward_once(&mut reopened, &agent, &limits(), now, write_cursor)?;
    assert_eq!(reopened.epoch, epoch_after);
    Ok(())
}


#[test]
fn a_symlinked_epoch_file_is_refused() -> TestResult {
    let root = TempDir::new()?;
    let target = root.path().join("elsewhere");
    fs::write(&target, "00000000000000000000000000000000\n")?;
    let spool_dir = root.path().join("spool");
    fs::create_dir(&spool_dir)?;
    symlink(&target, spool_dir.join(EPOCH_FILE))?;
    assert!(open_spool(&spool_dir, config()).is_err());
    assert!(load_epoch(&open_directory(&spool_dir)?).is_err());
    Ok(())
}


#[test]
fn an_epoch_file_that_is_a_fifo_is_refused_without_blocking() -> TestResult {
    let root = TempDir::new()?;
    let spool_dir = root.path().join("spool");
    fs::create_dir(&spool_dir)?;
    assert!(Command::new("mkfifo").arg(spool_dir.join(EPOCH_FILE)).status()?.success());
    assert!(open_spool(&spool_dir, config()).is_err());
    Ok(())
}


#[test]
fn a_blocked_epoch_write_is_reported() -> TestResult {
    let root = TempDir::new()?;
    fs::create_dir(root.path().join("spool.epoch.tmp"))?;
    let handle = open_directory(root.path())?;
    assert!(new_epoch(&handle).is_err());
    Ok(())
}


#[test]
fn an_unreadable_cursor_keeps_the_epoch() -> TestResult {
    let root = TempDir::new()?;
    let first = open_spool(root.path(), config())?;
    let epoch = first.epoch.clone();
    drop(first);
    fs::write(root.path().join(CURSOR_FILE), "junk")?;
    assert_eq!(open_spool(root.path(), config())?.epoch, epoch);
    Ok(())
}


fn failing_cursor(_dir: &DirHandle, _next: u64) -> std::io::Result<()> {
    Err(std::io::Error::other("injected cursor failure"))
}


#[test]
fn a_forward_with_a_failing_cursor_keeps_its_records_and_the_epoch_across_a_reopen() -> TestResult {
    let root = TempDir::new()?;
    let agent = root.path().join("agent.spool");
    let spool_dir = root.path().join("spool");
    fs::create_dir(&spool_dir)?;
    let now = OffsetDateTime::from_unix_timestamp(NOW_SECONDS)?;
    let mut spool = open_spool(&spool_dir, config())?;
    (0..FRAMES_IN_TOTAL).try_for_each(|_| append(&mut spool, Priority::Low, GOOD).map(|_| ()))?;
    assert!(forward_once(&mut spool, &agent, &limits(), now, failing_cursor).is_err());
    let epoch = spool.epoch.clone();
    let next = spool_stats(&spool).next_sequence;
    drop(spool);
    let reopened = open_spool(&spool_dir, config())?;
    assert_eq!(reopened.epoch, epoch);
    assert_eq!(spool_stats(&reopened).next_sequence, next);
    assert_eq!(epochs_of(&agent)?.len(), FRAMES_IN_TOTAL as usize);
    sync_from(&reopened, 1)?;
    Ok(())
}
