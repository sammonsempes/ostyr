use crate::bounds::Capture;
use crate::spool_append::agent_file;
use crate::types::TestResult;
use agent_channel::proto::EventBatch;
use agent_channel::spool::{
    claim_spool, copy_after_excess, line_limit, quarantine, quarantine_refused, rewrite_quarantine_with, RefusedLines, MAX_QUARANTINED_LINES,
    MAX_REFUSAL_WARNINGS, MAX_REJECTED_BYTES, MAX_REJECTED_LINES,
};
use std::fs::{self, File};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;


const BAD_LINE: &[u8] = b"<\x30\x82MARKER\xff\xfe>\n";


const MANY_BAD_LINES: usize = 300;


const BIG_BAD_LINES: usize = 20;


const BIG_BAD_BYTES: usize = 400_000;


const PASSES: usize = 2;


const NEW_BYTES: u64 = 10;


fn captured_log() -> (Arc<Mutex<Vec<u8>>>, tracing::subscriber::DefaultGuard) {
    let captured = Arc::new(Mutex::new(Vec::new()));
    let writer = Capture(Arc::clone(&captured));
    let subscriber = tracing_subscriber::fmt().with_writer(move || writer.clone()).with_ansi(false).finish();
    (captured, tracing::subscriber::set_default(subscriber))
}


fn texts(batches: &[EventBatch]) -> Vec<String> {
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
fn a_quarantine_that_cannot_be_opened_or_written_is_an_error() -> TestResult {
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
    assert!(quarantine_refused(&spool, &refused).is_err());
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


fn open_the_directory(path: &Path) -> io::Result<Option<File>> {
    File::open(path.parent().ok_or(io::ErrorKind::NotFound)?).map(Some)
}


fn refuse_the_file(_: &Path) -> io::Result<Option<File>> {
    Err(io::ErrorKind::PermissionDenied.into())
}


#[test]
fn a_copying_pass_that_cannot_read_or_open_the_old_quarantine_fails_and_keeps_it() -> TestResult {
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    fs::write(&rejected, "keep\n")?;
    let added = vec!["new".to_owned()];
    assert!(rewrite_quarantine_with(&rejected, &added, NEW_BYTES, (MAX_REJECTED_BYTES, MAX_REJECTED_LINES), open_the_directory).is_err());
    assert!(rewrite_quarantine_with(&rejected, &added, NEW_BYTES, (MAX_REJECTED_BYTES, MAX_REJECTED_LINES), refuse_the_file).is_err());
    assert_eq!(fs::read_to_string(&rejected)?, "keep\n");
    Ok(())
}


const FILES_AFTER_REWRITE: usize = 2;


fn no_old_file(_: &Path) -> io::Result<Option<File>> {
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
fn a_rewrite_that_cannot_rename_over_the_quarantine_fails_and_leaves_no_temporary_file() -> TestResult {
    let dir = tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    fs::create_dir(&rejected)?;
    let added = vec!["new".to_owned()];
    assert!(rewrite_quarantine_with(&rejected, &added, NEW_BYTES, (MAX_REJECTED_BYTES, MAX_REJECTED_LINES), no_old_file).is_err());
    assert_eq!(fs::read_dir(dir.path())?.count(), 1);
    Ok(())
}


#[test]
fn a_copying_pass_that_fails_to_read_the_old_handle_is_an_error() -> TestResult {
    let dir = tempdir()?;
    let handle = File::open(dir.path())?;
    let mut skipped = RefusedLines::default();
    let mut out = Vec::new();
    assert!(copy_after_excess(Some(&handle), (0, 0), &mut skipped, &mut out).is_err());
    assert!(out.is_empty());
    Ok(())
}
