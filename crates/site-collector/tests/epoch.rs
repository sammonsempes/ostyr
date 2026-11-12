#![cfg(unix)]

#[path = "support/types.rs"]
mod types;


use serde_json::Value;
use site_collector::dirfs::open_directory;
use site_collector::epoch::{load_epoch, new_epoch, valid_epoch};
use site_collector::error::SpoolError;
use site_collector::forward::{forward_once, read_cursor, write_cursor};
use site_collector::forward_model::{ForwardLimits, CURSOR_FILE, EPOCH_FILE};
use site_collector::listen_model::ListenerKind;
use site_collector::spool::{append, open_spool, segment_name, spool_stats, sync_range, sync_range_with};
use site_collector::spool_model::{Priority, Spool, SpoolConfig, MAX_FRAME_BYTES};
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


const BIG_PADDING: usize = 3000;


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
        kind: ListenerKind::Syslog,
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
    forward_once(&mut spool, &agent, &limits(), now, write_cursor, sync_range)?;
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
    let report = forward_once(&mut reopened, &agent, &limits(), now, write_cursor, sync_range)?;
    assert_eq!(report.forwarded, 1);
    assert_eq!(fs::read_to_string(spool_dir.join(EPOCH_FILE))?.trim(), reopened.epoch);
    let handle = open_directory(&spool_dir)?;
    assert_eq!(read_cursor(&handle)?, 1);
    let epochs = epochs_of(&agent)?;
    assert_eq!(epochs.len(), FRAMES_IN_TOTAL as usize + 1);
    assert_eq!(epochs.last(), Some(&reopened.epoch));
    assert_eq!(epochs.first(), Some(&old_epoch));
    let epoch_after = reopened.epoch.clone();
    forward_once(&mut reopened, &agent, &limits(), now, write_cursor, sync_range)?;
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
    assert!(forward_once(&mut spool, &agent, &limits(), now, failing_cursor, sync_range).is_err());
    let epoch = spool.epoch.clone();
    let next = spool_stats(&spool).next_sequence;
    drop(spool);
    let reopened = open_spool(&spool_dir, config())?;
    assert_eq!(reopened.epoch, epoch);
    assert_eq!(spool_stats(&reopened).next_sequence, next);
    assert_eq!(epochs_of(&agent)?.len(), FRAMES_IN_TOTAL as usize);
    Ok(())
}


fn failing_sync(_spool: &Spool, _from: u64, _to: u64) -> Result<(), SpoolError> {
    Err(SpoolError::Io(std::io::Error::other("injected sync failure")))
}


fn range_sync(_spool: &Spool, from: u64, to: u64) -> Result<(), SpoolError> {
    ((from, to) == (0, FRAMES_IN_TOTAL))
        .then_some(())
        .ok_or_else(|| SpoolError::Io(std::io::Error::other(format!("unexpected range {from}-{to}"))))
}


fn filled_spool(spool_dir: &Path, frames: u64) -> Result<Spool, Box<dyn std::error::Error>> {
    fs::create_dir_all(spool_dir)?;
    let mut spool = open_spool(spool_dir, config())?;
    let payload = [GOOD, &[b'x'; BIG_PADDING]].concat();
    (0..frames).try_for_each(|_| append(&mut spool, Priority::Low, &payload).map(|_| ()))?;
    Ok(spool)
}


#[test]
fn a_failing_sync_appends_nothing_and_keeps_the_cursor() -> TestResult {
    let root = TempDir::new()?;
    let agent = root.path().join("agent.spool");
    let spool_dir = root.path().join("spool");
    let mut spool = filled_spool(&spool_dir, FRAMES_IN_TOTAL)?;
    let now = OffsetDateTime::from_unix_timestamp(NOW_SECONDS)?;
    assert!(forward_once(&mut spool, &agent, &limits(), now, write_cursor, failing_sync).is_err());
    assert!(!agent.exists());
    assert_eq!(read_cursor(&open_directory(&spool_dir)?)?, 0);
    Ok(())
}


#[test]
fn the_sync_gets_the_batch_range_and_is_skipped_for_an_empty_batch() -> TestResult {
    let root = TempDir::new()?;
    let agent = root.path().join("agent.spool");
    let spool_dir = root.path().join("spool");
    let mut spool = filled_spool(&spool_dir, FRAMES_IN_TOTAL)?;
    let now = OffsetDateTime::from_unix_timestamp(NOW_SECONDS)?;
    forward_once(&mut spool, &agent, &limits(), now, write_cursor, range_sync)?;
    assert_eq!(forward_once(&mut spool, &agent, &limits(), now, write_cursor, failing_sync)?.forwarded, 0);
    Ok(())
}


#[test]
fn a_batch_over_rotated_segments_is_synced_for_real() -> TestResult {
    let root = TempDir::new()?;
    let agent = root.path().join("agent.spool");
    let spool_dir = root.path().join("spool");
    let mut spool = filled_spool(&spool_dir, FRAMES_IN_TOTAL)?;
    assert!(spool_stats(&spool).segments > 1);
    let now = OffsetDateTime::from_unix_timestamp(NOW_SECONDS)?;
    let report = forward_once(&mut spool, &agent, &limits(), now, write_cursor, sync_range)?;
    assert_eq!(report.forwarded, FRAMES_IN_TOTAL);
    Ok(())
}


#[test]
fn only_the_segments_holding_the_range_are_synced() -> TestResult {
    let root = TempDir::new()?;
    let spool_dir = root.path().join("spool");
    let spool = filled_spool(&spool_dir, FRAMES_IN_TOTAL)?;
    fs::remove_file(spool_dir.join(segment_name(0)))?;
    sync_range(&spool, 1, FRAMES_IN_TOTAL)?;
    assert!(sync_range(&spool, 0, 1).is_err());
    fs::remove_file(spool_dir.join(segment_name(FRAMES_IN_TOTAL - 1)))?;
    sync_range(&spool, 1, FRAMES_IN_TOTAL - 1)?;
    assert!(sync_range(&spool, 1, FRAMES_IN_TOTAL).is_err());
    Ok(())
}


fn failing_directory_sync(_dir: &DirHandle) -> std::io::Result<()> {
    Err(std::io::Error::other("injected directory sync failure"))
}


fn sync_with_failing_directory(spool: &Spool, from: u64, to: u64) -> Result<(), SpoolError> {
    sync_range_with(spool, from, to, failing_directory_sync)
}


#[test]
fn a_failing_directory_sync_after_a_rotation_appends_nothing_and_keeps_the_cursor() -> TestResult {
    let root = TempDir::new()?;
    let agent = root.path().join("agent.spool");
    let spool_dir = root.path().join("spool");
    let mut spool = filled_spool(&spool_dir, FRAMES_IN_TOTAL)?;
    assert!(spool_stats(&spool).segments > 1);
    let now = OffsetDateTime::from_unix_timestamp(NOW_SECONDS)?;
    assert!(forward_once(&mut spool, &agent, &limits(), now, write_cursor, sync_with_failing_directory).is_err());
    assert!(!agent.exists());
    assert_eq!(read_cursor(&open_directory(&spool_dir)?)?, 0);
    Ok(())
}
