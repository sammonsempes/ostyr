use crate::bounds::Capture;
use crate::spool_append::agent_file;
use crate::types::TestResult;
use agent_channel::proto::EventBatch;
use agent_channel::spool::{
    claim_spool, copy_after_excess, directory_of, line_limit, open_old, quarantine, quarantine_refused, remove_regular_file,
    remove_stale_temporaries, rewrite_quarantine_with, RefusedLines, MAX_QUARANTINED_LINES, MAX_REFUSAL_WARNINGS, MAX_REJECTED_BYTES,
    MAX_REJECTED_LINES, QUARANTINE_LOCK_BUSY, QUARANTINE_TEMPORARY_INFIX,
};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;


pub const BAD_LINE: &[u8] = b"<\x30\x82MARKER\xff\xfe>\n";


const MANY_BAD_LINES: usize = 300;


const BIG_BAD_LINES: usize = 20;


const BIG_BAD_BYTES: usize = 400_000;


const PASSES: usize = 2;


pub const NEW_BYTES: u64 = 10;


pub fn captured_log() -> (Arc<Mutex<Vec<u8>>>, tracing::subscriber::DefaultGuard) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let subscriber = tracing_subscriber::fmt().with_writer(move || writer.clone()).with_ansi(false).finish();
    (captured, tracing::subscriber::set_default(subscriber))
}


pub fn texts(batches: &[EventBatch]) -> Vec<String> {
    batches
        .iter()
        .map(|batch| String::from_utf8_lossy(&batch.ecs_json).into_owned())
        .collect()
}


#[test]
fn a_bad_line_is_refused_alone_and_the_good_ones_around_it_are_claimed() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    let mut spool = b"good1\n".to_vec();
    spool.extend_from_slice(BAD_LINE);
    spool.extend_from_slice(b"good2\n");
    fs::write(&file.spool_file, spool)?;
    let claimed = claim_spool(&file)?;
    assert_eq!(texts(&claimed.batches), vec!["good1".to_owned(), "good2".to_owned()]);
    assert_eq!(fs::read_to_string(&file.sequence_file)?, "2 2\n");
    assert_eq!(
        fs::read_to_string(dir.path().join("spool.rejected"))?,
        "<0\u{fffd}MARKER\u{fffd}\u{fffd}>\n"
    );
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("line=2"), "{log}");
    assert!(log.contains("valid_up_to=2"), "{log}");
    assert!(!log.contains("MARKER") && !log.contains("48, 130"), "{log}");
    Ok(())
}


#[test]
fn a_spool_of_bad_lines_only_claims_nothing_and_quarantines_each() -> TestResult {
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    fs::write(&file.spool_file, [BAD_LINE, b"\xc3\n"].concat())?;
    let claimed = claim_spool(&file)?;
    assert!(claimed.batches.is_empty());
    assert!(!dir.path().join("spool.sending").exists());
    assert_eq!(fs::metadata(&file.spool_file)?.len(), 0);
    assert_eq!(
        fs::read_to_string(dir.path().join("spool.rejected"))?,
        "<0\u{fffd}MARKER\u{fffd}\u{fffd}>\n\u{fffd}\n"
    );
    Ok(())
}


#[test]
fn many_bad_lines_never_hide_the_good_one_behind_them() -> TestResult {
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    let mut spool = BAD_LINE.repeat(MANY_BAD_LINES);
    spool.extend_from_slice(b"good\n");
    fs::write(&file.spool_file, spool)?;
    let claimed = claim_spool(&file)?;
    assert_eq!(texts(&claimed.batches), vec!["good".to_owned()]);
    assert_eq!(fs::read_to_string(&file.sequence_file)?, "1 1\n");
    assert_eq!(fs::read_to_string(dir.path().join("spool.rejected"))?.lines().count(), MANY_BAD_LINES);
    Ok(())
}


#[test]
fn bad_lines_over_the_quarantine_budget_are_counted_and_the_good_line_still_goes() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    let mut spool = [vec![u8::MAX; BIG_BAD_BYTES], b"\n".to_vec()].concat().repeat(BIG_BAD_LINES);
    spool.extend_from_slice(b"good\n");
    fs::write(&file.spool_file, spool)?;
    let claimed = claim_spool(&file)?;
    assert_eq!(texts(&claimed.batches), vec!["good".to_owned()]);
    assert!(fs::metadata(dir.path().join("spool.rejected"))?.len() <= MAX_REJECTED_BYTES);
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("dropped=4"), "{log}");
    Ok(())
}


#[test]
fn a_hostile_bad_line_logs_one_line_per_pass_without_its_bytes() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    fs::write(&file.spool_file, b"good\n{\"a\":\"\r\x1b[31m\xff\"}\n")?;
    claim_spool(&file)?;
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert_eq!(log.lines().filter(|line| line.contains("non-UTF-8")).count(), PASSES);
    assert!(!log.contains('\r') && !log.contains('\u{1b}') && !log.contains("[31m"), "{log:?}");
    Ok(())
}


const ONE_BYTE_BAD_LINES: usize = 5_000;


const OVERSIZED_LINES: usize = 12;


const SLACK_BYTES: usize = 1;


const ROOM_BYTES: u64 = 6;


const SMALL_BYTES: u64 = 2;


fn count_of(log: &str, needle: &str) -> usize {
    log.lines().filter(|line| line.contains(needle)).count()
}


#[test]
fn thousands_of_one_byte_bad_lines_keep_a_capped_quarantine_and_a_bounded_log() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    let mut spool = b"\xff\n".repeat(ONE_BYTE_BAD_LINES);
    spool.extend_from_slice(b"good\n");
    fs::write(&file.spool_file, spool)?;
    let claimed = claim_spool(&file)?;
    assert_eq!(texts(&claimed.batches), vec!["good".to_owned()]);
    assert_eq!(
        fs::read_to_string(dir.path().join("spool.rejected"))?.lines().count(),
        MAX_QUARANTINED_LINES
    );
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert_eq!(
        count_of(&log, "non-UTF-8 spool line refused"),
        PASSES * MAX_REFUSAL_WARNINGS as usize,
        "{log}"
    );
    assert_eq!(count_of(&log, "spool lines refused"), PASSES, "{log}");
    assert!(log.contains(&format!("dropped={}", ONE_BYTE_BAD_LINES - MAX_QUARANTINED_LINES)), "{log}");
    Ok(())
}


#[test]
fn an_all_bad_spool_of_one_byte_lines_is_emptied_with_a_capped_quarantine() -> TestResult {
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    fs::write(&file.spool_file, b"\xff\n".repeat(ONE_BYTE_BAD_LINES))?;
    let claimed = claim_spool(&file)?;
    assert!(claimed.batches.is_empty());
    assert_eq!(fs::metadata(&file.spool_file)?.len(), 0);
    assert_eq!(
        fs::read_to_string(dir.path().join("spool.rejected"))?.lines().count(),
        MAX_QUARANTINED_LINES
    );
    Ok(())
}


#[test]
fn oversized_lines_are_logged_up_to_the_cap_then_summarised() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    let big = [vec![b'a'; line_limit(&file) + SLACK_BYTES], b"\n".to_vec()].concat();
    let mut spool = big.repeat(OVERSIZED_LINES);
    spool.extend_from_slice(b"good\n");
    fs::write(&file.spool_file, spool)?;
    let claimed = claim_spool(&file)?;
    assert_eq!(texts(&claimed.batches), vec!["good".to_owned()]);
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert_eq!(
        count_of(&log, "oversized spool line refused"),
        PASSES * MAX_REFUSAL_WARNINGS as usize,
        "{log}"
    );
    assert_eq!(count_of(&log, "spool lines refused"), PASSES, "{log}");
    Ok(())
}


#[test]
fn the_oldest_quarantine_lines_make_room_for_new_ones_in_one_stream() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let rejected = dir.path().join("spool.rejected");
    fs::write(&rejected, "aaaa\nbbbb\ncccc\n")?;
    let refused = RefusedLines {
        lines: vec!["new".to_owned()],
        bytes: MAX_REJECTED_BYTES - ROOM_BYTES,
        ..RefusedLines::default()
    };
    quarantine_refused(&spool, &refused)?;
    assert_eq!(fs::read_to_string(&rejected)?, "cccc\nnew\n");
    quarantine_refused(&spool, &RefusedLines::default())?;
    assert_eq!(fs::read_to_string(&rejected)?, "cccc\nnew\n");
    Ok(())
}


#[test]
fn a_quarantine_in_an_unusable_directory_is_an_error_and_a_directory_in_its_place_is_not() -> TestResult {
    let dir = tempdir()?;
    let refused = RefusedLines {
        lines: vec!["x".to_owned()],
        bytes: SMALL_BYTES,
        ..RefusedLines::default()
    };
    let blocker = dir.path().join("blocker");
    fs::write(&blocker, "file")?;
    assert!(quarantine_refused(&blocker.join("spool"), &refused).is_err());
    let spool = dir.path().join("spool");
    fs::create_dir(dir.path().join("spool.rejected"))?;
    assert!(quarantine_refused(&spool, &refused).is_ok());
    Ok(())
}


fn numbered_lines(count: u64) -> String {
    (0..count).map(|number| format!("old{number}\n")).collect()
}


#[test]
fn the_quarantine_never_holds_more_than_its_line_cap_across_claims() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    let rejected = dir.path().join("spool.rejected");
    fs::write(&rejected, numbered_lines(MAX_REJECTED_LINES))?;
    let refused = RefusedLines {
        lines: vec!["new1".to_owned(), "new2".to_owned()],
        bytes: NEW_BYTES,
        ..RefusedLines::default()
    };
    quarantine_refused(&spool, &refused)?;
    let text = fs::read_to_string(&rejected)?;
    let lines = text.lines().collect::<Vec<_>>();
    assert_eq!(lines.len() as u64, MAX_REJECTED_LINES);
    assert_eq!(lines.first(), Some(&"old2"));
    assert_eq!(lines.last(), Some(&"new2"));
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("dropped=2"), "{log}");
    Ok(())
}


#[test]
fn a_tail_cut_over_a_full_quarantine_keeps_the_line_cap_and_logs_a_refused_old_line() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    let mut old = numbered_lines(MAX_REJECTED_LINES - 1).into_bytes();
    old.extend_from_slice(BAD_LINE);
    fs::write(&rejected, old)?;
    let batch = EventBatch {
        ecs_json: b"tail".to_vec(),
        ..EventBatch::default()
    };
    assert_eq!(quarantine(&rejected, &[batch], MAX_REJECTED_BYTES)?, 0);
    let text = fs::read_to_string(&rejected)?;
    assert_eq!(text.lines().count() as u64, MAX_REJECTED_LINES);
    assert_eq!(text.lines().last(), Some("tail"));
    assert!(!text.contains("MARKER"));
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(
        log.contains("quarantine lines refused and not copied") && !log.contains("MARKER"),
        "{log}"
    );
    Ok(())
}


#[test]
fn a_tail_cut_over_a_quarantine_at_both_caps_drops_the_oldest_and_counts_them() -> TestResult {
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    fs::write(&rejected, numbered_lines(MAX_REJECTED_LINES))?;
    let batch = EventBatch {
        ecs_json: b"tail".to_vec(),
        ..EventBatch::default()
    };
    assert_eq!(quarantine(&rejected, &[batch], MAX_REJECTED_BYTES)?, 1);
    let text = fs::read_to_string(&rejected)?;
    assert_eq!(text.lines().next(), Some("old1"));
    assert_eq!(text.lines().count() as u64, MAX_REJECTED_LINES);
    Ok(())
}


fn open_unreadable(path: &Path) -> io::Result<Option<File>> {
    OpenOptions::new().write(true).open(path).map(Some)
}


fn refuse_the_file(_: &Path) -> io::Result<Option<File>> {
    Err(io::ErrorKind::PermissionDenied.into())
}


#[test]
fn a_copying_pass_that_cannot_read_or_open_the_old_quarantine_disables_the_rewrite_and_keeps_it() -> TestResult {
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    fs::write(&rejected, "keep\n")?;
    let added = vec!["new".to_owned()];
    assert_eq!(
        rewrite_quarantine_with(
            &rejected,
            &added,
            NEW_BYTES,
            (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
            (open_unreadable, ATTEMPTS)
        )?,
        None
    );
    assert_eq!(
        rewrite_quarantine_with(
            &rejected,
            &added,
            NEW_BYTES,
            (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
            (refuse_the_file, ATTEMPTS)
        )?,
        None
    );
    assert_eq!(fs::read_to_string(&rejected)?, "keep\n");
    Ok(())
}


const FILES_AFTER_REWRITE: usize = 3;


pub const ATTEMPTS: u32 = 2;


const FILES_AFTER_FAILED_REWRITE: usize = 2;


pub fn no_old_file(_: &Path) -> io::Result<Option<File>> {
    Ok(None)
}


#[test]
fn a_rewrite_never_uses_a_fixed_temporary_name() -> TestResult {
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    fs::create_dir(dir.path().join("spool.rejected.tmp"))?;
    let refused = RefusedLines {
        lines: vec!["x".to_owned()],
        bytes: SMALL_BYTES,
        ..RefusedLines::default()
    };
    quarantine_refused(&spool, &refused)?;
    assert_eq!(fs::read_to_string(dir.path().join("spool.rejected"))?, "x\n");
    assert_eq!(fs::read_dir(dir.path())?.count(), FILES_AFTER_REWRITE);
    Ok(())
}


#[test]
fn a_directory_at_the_quarantine_disables_it_for_the_run_and_nothing_is_written() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    fs::create_dir(&rejected)?;
    let added = vec!["new".to_owned(), "newer".to_owned()];
    let dropped = rewrite_quarantine_with(
        &rejected,
        &added,
        NEW_BYTES,
        (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
        (no_old_file, ATTEMPTS),
    )?;
    assert_eq!(dropped, None);
    assert!(rejected.is_dir());
    assert_eq!(fs::read_dir(&rejected)?.count(), 0);
    assert_eq!(fs::read_dir(dir.path())?.count(), FILES_AFTER_FAILED_REWRITE);
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("quarantine disabled for this run") && log.contains("refused=2"), "{log}");
    Ok(())
}


#[test]
fn a_directory_at_the_quarantine_never_stops_the_claim_or_the_tail_cut() -> TestResult {
    let dir = tempdir()?;
    let file = agent_file(dir.path());
    fs::create_dir(dir.path().join("spool.rejected"))?;
    let mut spool = b"good1\n".to_vec();
    spool.extend_from_slice(BAD_LINE);
    spool.extend_from_slice(b"good2\ntorn");
    fs::write(&file.spool_file, spool)?;
    let claimed = claim_spool(&file)?;
    assert_eq!(texts(&claimed.batches), vec!["good1".to_owned(), "good2".to_owned()]);
    assert!(dir.path().join("spool.rejected").is_dir());
    let torn = dir.path().join("torn-spool");
    fs::write(&torn, "a\nzzz")?;
    fs::create_dir(dir.path().join("torn-spool.rejected"))?;
    agent_channel::spool::append_back(vec![Ok("b".to_owned())].into_iter(), &torn)?;
    assert_eq!(fs::read_to_string(&torn)?, "a\nb\n");
    Ok(())
}


fn directory_appears(path: &Path) -> io::Result<Option<File>> {
    fs::create_dir(path)?;
    Ok(None)
}


#[test]
fn a_directory_that_appears_after_the_check_disables_the_rewrite_and_leaves_no_temporary_file() -> TestResult {
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    let added = vec!["new".to_owned()];
    let result = rewrite_quarantine_with(
        &rejected,
        &added,
        NEW_BYTES,
        (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
        (directory_appears, ATTEMPTS),
    );
    assert_eq!(result?, None);
    assert!(rejected.is_dir());
    assert_eq!(fs::read_dir(dir.path())?.count(), FILES_AFTER_FAILED_REWRITE);
    Ok(())
}


struct FailingReader;


impl io::Read for FailingReader {
    fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
        Err(io::ErrorKind::PermissionDenied.into())
    }
}


#[test]
fn a_copying_pass_that_fails_to_read_the_old_handle_is_an_error() -> TestResult {
    let mut skipped = RefusedLines::default();
    let mut out = Vec::new();
    let mut reader = FailingReader;
    assert!(copy_after_excess(Some(&mut reader), 1, ((0, 0), (1, 1)), &mut skipped, &mut out).is_err());
    assert!(out.is_empty());
    Ok(())
}


fn leftovers(dir: &Path) -> io::Result<Vec<String>> {
    fs::read_dir(dir)?
        .map(|entry| entry.map(|found| found.file_name().to_string_lossy().into_owned()))
        .filter(|name| name.as_ref().map_or(true, |text| text.contains(QUARANTINE_TEMPORARY_INFIX)))
        .collect()
}


#[test]
fn a_rewrite_removes_the_files_killed_rewrites_left_and_skips_other_entries() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let spool = dir.path().join("spool");
    fs::write(dir.path().join(".spool.rejected.quarantine-aaaaaa"), "x")?;
    fs::write(dir.path().join(".spool.rejected.quarantine-bbbbbb"), "y")?;
    fs::create_dir(dir.path().join(".spool.rejected.quarantine-dir"))?;
    fs::write(dir.path().join("unrelated"), "keep")?;
    let refused = RefusedLines {
        lines: vec!["x".to_owned()],
        bytes: SMALL_BYTES,
        ..RefusedLines::default()
    };
    quarantine_refused(&spool, &refused)?;
    assert_eq!(leftovers(dir.path())?, vec![".spool.rejected.quarantine-dir".to_owned()]);
    assert_eq!(fs::read_to_string(dir.path().join("unrelated"))?, "keep");
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("removed=2") && log.contains("left=1"), "{log}");
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_symlink_with_the_temporary_prefix_is_never_followed_and_a_symlink_quarantine_is_replaced() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let target = dir.path().join("target");
    fs::write(&target, "secret\n")?;
    std::os::unix::fs::symlink(&target, dir.path().join(".spool.rejected.quarantine-link"))?;
    let rejected = dir.path().join("spool.rejected");
    std::os::unix::fs::symlink(&target, &rejected)?;
    let refused = RefusedLines {
        lines: vec!["x".to_owned()],
        bytes: SMALL_BYTES,
        ..RefusedLines::default()
    };
    quarantine_refused(&dir.path().join("spool"), &refused)?;
    assert_eq!(fs::read_to_string(&rejected)?, "x\n");
    assert_eq!(fs::read_to_string(&target)?, "secret\n");
    assert!(fs::symlink_metadata(dir.path().join(".spool.rejected.quarantine-link"))?.is_symlink());
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("ignored and replaced"), "{log}");
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_pipe_at_the_quarantine_never_blocks_the_rewrite() -> TestResult {
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    let status = std::process::Command::new("mkfifo").arg(&rejected).status()?;
    assert!(status.success());
    let refused = RefusedLines {
        lines: vec!["x".to_owned()],
        bytes: SMALL_BYTES,
        ..RefusedLines::default()
    };
    quarantine_refused(&dir.path().join("spool"), &refused)?;
    assert_eq!(fs::read_to_string(&rejected)?, "x\n");
    Ok(())
}


#[test]
fn a_rewrite_that_cannot_get_the_quarantine_lock_fails_and_changes_nothing() -> TestResult {
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    fs::write(&rejected, "keep\n")?;
    let holder = File::create(dir.path().join("spool.rejected.lock"))?;
    holder.lock()?;
    let added = vec!["new".to_owned()];
    assert!(rewrite_quarantine_with(
        &rejected,
        &added,
        NEW_BYTES,
        (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
        (open_old, ATTEMPTS)
    )
    .is_err());
    assert_eq!(fs::read_to_string(&rejected)?, "keep\n");
    Ok(())
}


#[test]
fn a_bare_file_name_has_the_current_directory_and_a_bad_directory_is_an_error() -> TestResult {
    assert_eq!(directory_of(Path::new("spool.rejected")), Path::new("."));
    assert_eq!(directory_of(Path::new("/a/spool.rejected")), Path::new("/a"));
    assert!(remove_stale_temporaries(Path::new("/nonexistent-t590-dir"), ".x", remove_regular_file).is_err());
    Ok(())
}


#[test]
fn an_old_refused_line_is_reported_once_with_quarantine_wording() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    let mut old = b"good\n".to_vec();
    old.extend_from_slice(BAD_LINE);
    old.extend(std::iter::repeat_n(b'a', agent_channel::model::DEFAULT_MAX_MESSAGE_BYTES + 1));
    old.push(b'\n');
    fs::write(&rejected, old)?;
    let added = vec!["new".to_owned()];
    rewrite_quarantine_with(
        &rejected,
        &added,
        NEW_BYTES,
        (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
        (open_old, ATTEMPTS),
    )?;
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert_eq!(log.matches("non-UTF-8 quarantine line refused").count(), 1, "{log}");
    assert_eq!(log.matches("oversized quarantine line refused").count(), 1, "{log}");
    assert!(!log.contains("spool line refused"), "{log}");
    Ok(())
}


#[test]
fn a_missing_old_quarantine_is_none() -> TestResult {
    let dir = tempdir()?;
    assert!(open_old(&dir.path().join("absent"))?.is_none());
    Ok(())
}


#[cfg(unix)]
#[test]
fn an_old_quarantine_that_cannot_be_opened_for_another_reason_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let blocker = dir.path().join("blocker");
    fs::write(&blocker, "file")?;
    assert!(open_old(&blocker.join("spool.rejected")).is_err());
    Ok(())
}


fn refuse_removal(_: &Path) -> io::Result<()> {
    Err(io::ErrorKind::PermissionDenied.into())
}


#[test]
fn a_leftover_that_cannot_be_removed_is_skipped_and_counted_and_only_this_quarantines_are_touched() -> TestResult {
    let dir = tempdir()?;
    fs::write(dir.path().join(".spool.rejected.quarantine-aaaaaa"), "x")?;
    fs::write(dir.path().join(".other.rejected.quarantine-bbbbbb"), "y")?;
    assert_eq!(
        remove_stale_temporaries(dir.path(), ".spool.rejected.quarantine-", refuse_removal)?,
        (0, 1)
    );
    assert_eq!(
        remove_stale_temporaries(dir.path(), ".spool.rejected.quarantine-", remove_regular_file)?,
        (1, 0)
    );
    assert_eq!(leftovers(dir.path())?, vec![".other.rejected.quarantine-bbbbbb".to_owned()]);
    let refused = RefusedLines {
        lines: vec!["x".to_owned()],
        bytes: SMALL_BYTES,
        ..RefusedLines::default()
    };
    quarantine_refused(&dir.path().join("spool"), &refused)?;
    assert_eq!(leftovers(dir.path())?, vec![".other.rejected.quarantine-bbbbbb".to_owned()]);
    Ok(())
}


#[test]
fn a_busy_quarantine_lock_has_its_own_error_text() -> TestResult {
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    let holder = File::create(dir.path().join("spool.rejected.lock"))?;
    holder.lock()?;
    let added = vec!["new".to_owned()];
    let error = rewrite_quarantine_with(
        &rejected,
        &added,
        NEW_BYTES,
        (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
        (open_old, ATTEMPTS),
    )
    .err()
    .ok_or("no error")?;
    assert_eq!(error.to_string(), QUARANTINE_LOCK_BUSY);
    Ok(())
}
