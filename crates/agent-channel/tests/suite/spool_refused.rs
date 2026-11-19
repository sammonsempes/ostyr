use crate::bounds::Capture;
use crate::spool_append::agent_file;
use crate::types::TestResult;
use agent_channel::proto::EventBatch;
use agent_channel::spool::{
    claim_spool, line_limit, quarantine_refused, RefusedLines, MAX_QUARANTINED_LINES, MAX_REFUSAL_WARNINGS, MAX_REJECTED_BYTES,
};
use std::fs;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;


const BAD_LINE: &[u8] = b"<\x30\x82MARKER\xff\xfe>\n";


const MANY_BAD_LINES: usize = 300;


const BIG_BAD_LINES: usize = 20;


const BIG_BAD_BYTES: usize = 400_000;


const PASSES: usize = 2;


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
    fs::create_dir(dir.path().join("spool.rejected.tmp"))?;
    assert!(quarantine_refused(&spool, &refused).is_err());
    fs::remove_dir(dir.path().join("spool.rejected.tmp"))?;
    fs::create_dir(dir.path().join("spool.rejected"))?;
    assert!(quarantine_refused(&spool, &refused).is_err());
    Ok(())
}
