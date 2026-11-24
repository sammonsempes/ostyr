use crate::harness::long_tempdir;
use crate::spool_append::agent_file;
use crate::spool_refused::{captured_log, texts, ATTEMPTS, BAD_LINE, NEW_BYTES};
use crate::types::TestResult;
use agent_channel::spool::{
    claim_spool, copy_after_excess, is_not_a_regular_file, old_totals, open_old, rewrite_quarantine_with, unusable_reason, RefusedLines,
    MAX_REJECTED_BYTES, MAX_REJECTED_LINES,
};
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::Path;


const MARKER: &str = "OLDMARKER";


const WARNINGS_OF_TWO_RUNS: usize = 2;


const LINE_BYTES: usize = 1_000;


const FOREIGN_EUID: u32 = 4_294_967_294;


const NOBODY: u32 = 65_534;


const PASS_LINES: u64 = 10;


const EXTRA_LINES: u64 = 5;


const ROOM_LINES: u64 = 3;


const ROOM_BYTE_LINES: u64 = 4;


fn open_with_too_many_files(_: &Path) -> io::Result<Option<File>> {
    Err(io::Error::from_raw_os_error(rustix::io::Errno::MFILE.raw_os_error()))
}


struct Supply {
    line: Vec<u8>,
    position: usize,
    handed_out: u64,
    supply: u64,
}


impl Read for Supply {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let room = usize::try_from(self.supply - self.handed_out).unwrap_or(usize::MAX);
        let count = buffer
            .iter_mut()
            .take(room)
            .zip(self.line.iter().cycle().skip(self.position))
            .map(|(slot, byte)| *slot = *byte)
            .count();
        self.position = (self.position + count) % self.line.len();
        self.handed_out += count as u64;
        Ok(count)
    }
}


fn lines_supply(supply: u64) -> Supply {
    let mut line = vec![b'a'; LINE_BYTES - 1];
    line.push(b'\n');
    Supply {
        line,
        position: 0,
        handed_out: 0,
        supply,
    }
}


fn rewrite_with(path: &Path, open: fn(&Path) -> io::Result<Option<File>>) -> io::Result<Option<u64>> {
    rewrite_quarantine_with(
        path,
        &["new".to_owned()],
        NEW_BYTES,
        (MAX_REJECTED_BYTES, MAX_REJECTED_LINES),
        (open, ATTEMPTS),
    )
}


#[test]
fn an_unusable_quarantine_has_one_reason_each() -> TestResult {
    let dir = long_tempdir()?;
    let regular = dir.path().join("regular");
    fs::write(&regular, "x\n")?;
    let metadata = fs::metadata(&regular)?;
    assert_eq!(unusable_reason(&metadata, agent_channel::spool::effective_uid()), None);
    assert_eq!(
        unusable_reason(&fs::metadata(dir.path())?, agent_channel::spool::effective_uid()),
        Some("not a regular file")
    );
    let big = dir.path().join("big");
    File::create(&big)?.set_len(MAX_REJECTED_BYTES + 1)?;
    assert_eq!(
        unusable_reason(&fs::metadata(&big)?, agent_channel::spool::effective_uid()),
        Some("over the size cap")
    );
    let exact = dir.path().join("exact");
    File::create(&exact)?.set_len(MAX_REJECTED_BYTES)?;
    assert_eq!(unusable_reason(&fs::metadata(&exact)?, agent_channel::spool::effective_uid()), None);
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_foreign_owner_and_a_hard_link_are_unusable_reasons() -> TestResult {
    let dir = long_tempdir()?;
    let regular = dir.path().join("regular");
    fs::write(&regular, "x\n")?;
    let own = agent_channel::spool::effective_uid();
    assert_eq!(unusable_reason(&fs::metadata(&regular)?, FOREIGN_EUID), Some("foreign owner"));
    fs::hard_link(&regular, dir.path().join("second-name"))?;
    assert_eq!(unusable_reason(&fs::metadata(&regular)?, own), Some("hard linked"));
    Ok(())
}


#[test]
fn an_oversized_old_quarantine_is_replaced_never_read_and_logged_once() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = long_tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    let mut sparse = File::create(&rejected)?;
    io::Write::write_all(&mut sparse, MARKER.as_bytes())?;
    sparse.set_len(MAX_REJECTED_BYTES + 1)?;
    assert!(open_old(&rejected)?.is_none());
    assert_eq!(rewrite_with(&rejected, open_old)?, Some(0));
    assert_eq!(fs::read_to_string(&rejected)?, "new\n");
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert_eq!(
        log.matches("quarantine entry unusable, ignored and replaced").count(),
        WARNINGS_OF_TWO_RUNS,
        "{log}"
    );
    assert!(log.contains("over the size cap"), "{log}");
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_hard_link_at_the_quarantine_is_replaced_and_its_bytes_never_reach_the_new_file() -> TestResult {
    let dir = long_tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    let other = dir.path().join("other-name");
    fs::write(&other, format!("{MARKER}\n"))?;
    fs::hard_link(&other, &rejected)?;
    assert_eq!(rewrite_with(&rejected, open_old)?, Some(0));
    assert_eq!(fs::read_to_string(&rejected)?, "new\n");
    assert_eq!(fs::read_to_string(&other)?, format!("{MARKER}\n"));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_foreign_owned_quarantine_is_replaced_and_its_bytes_never_reach_the_new_file() -> TestResult {
    let dir = long_tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    fs::write(&rejected, format!("{MARKER}\n"))?;
    let owner = rustix::fs::Uid::from_raw(NOBODY);
    rustix::fs::chownat(rustix::fs::CWD, &rejected, Some(owner), None, rustix::fs::AtFlags::empty())?;
    assert_eq!(rewrite_with(&rejected, open_old)?, Some(0));
    assert_eq!(fs::read_to_string(&rejected)?, "new\n");
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_lease_break_refusal_is_not_a_regular_file() -> TestResult {
    assert!(is_not_a_regular_file(&io::Error::from_raw_os_error(
        rustix::io::Errno::WOULDBLOCK.raw_os_error()
    )));
    Ok(())
}


#[cfg(unix)]
#[test]
fn a_transient_open_error_disables_the_rewrite_and_keeps_the_old_file_byte_for_byte() -> TestResult {
    let (captured, _guard) = captured_log();
    let dir = long_tempdir()?;
    let rejected = dir.path().join("spool.rejected");
    fs::write(&rejected, format!("{MARKER}\n"))?;
    assert_eq!(rewrite_with(&rejected, open_with_too_many_files)?, None);
    assert_eq!(fs::read_to_string(&rejected)?, format!("{MARKER}\n"));
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("quarantine rewrite failed, quarantine disabled for this run"), "{log}");
    assert!(!log.contains("ignored and replaced"), "{log}");
    Ok(())
}


#[test]
fn the_counting_pass_reads_at_most_the_cap_from_a_source_with_more_to_give() -> TestResult {
    let mut source = lines_supply(MAX_REJECTED_BYTES + EXTRA_LINES * LINE_BYTES as u64);
    let (lines, bytes, consumed) = old_totals(Some(&mut source))?;
    assert_eq!(consumed, MAX_REJECTED_BYTES);
    assert_eq!(source.handed_out, MAX_REJECTED_BYTES);
    assert_eq!(bytes, lines * LINE_BYTES as u64);
    assert!(lines > 0);
    Ok(())
}


#[test]
fn the_copy_pass_reads_at_most_what_the_counting_pass_read() -> TestResult {
    let mut source = lines_supply(EXTRA_LINES * LINE_BYTES as u64 + PASS_LINES * LINE_BYTES as u64);
    let mut out = Vec::new();
    let mut refused = RefusedLines::default();
    let consumed = PASS_LINES * LINE_BYTES as u64;
    let dropped = copy_after_excess(Some(&mut source), consumed, ((0, 0), (u64::MAX, u64::MAX)), &mut refused, &mut out)?;
    assert_eq!(source.handed_out, consumed);
    assert_eq!(dropped, 0);
    assert_eq!(out.len() as u64, consumed);
    Ok(())
}


#[test]
fn the_copy_pass_never_writes_past_the_room_whatever_the_old_file_became() -> TestResult {
    let mut by_lines = Vec::new();
    let mut by_bytes = Vec::new();
    let mut refused = RefusedLines::default();
    let consumed = PASS_LINES * LINE_BYTES as u64;
    let dropped_by_lines = copy_after_excess(
        Some(&mut lines_supply(EXTRA_LINES * LINE_BYTES as u64 + PASS_LINES * LINE_BYTES as u64)),
        consumed,
        ((0, 0), (u64::MAX, ROOM_LINES)),
        &mut refused,
        &mut by_lines,
    )?;
    assert_eq!(by_lines.len() as u64, ROOM_LINES * LINE_BYTES as u64);
    assert_eq!(dropped_by_lines, PASS_LINES - ROOM_LINES);
    let room_bytes = ROOM_BYTE_LINES * LINE_BYTES as u64 + 1;
    let dropped_by_bytes = copy_after_excess(
        Some(&mut lines_supply(EXTRA_LINES * LINE_BYTES as u64 + PASS_LINES * LINE_BYTES as u64)),
        consumed,
        ((0, 0), (room_bytes, u64::MAX)),
        &mut refused,
        &mut by_bytes,
    )?;
    assert_eq!(by_bytes.len() as u64, ROOM_BYTE_LINES * LINE_BYTES as u64);
    assert_eq!(dropped_by_bytes, PASS_LINES - ROOM_BYTE_LINES);
    Ok(())
}


#[cfg(unix)]
#[test]
fn an_oversized_and_a_hard_linked_quarantine_never_stop_the_claim() -> TestResult {
    let dir = long_tempdir()?;
    let file = agent_file(dir.path());
    let rejected = dir.path().join("spool.rejected");
    File::create(&rejected)?.set_len(MAX_REJECTED_BYTES + 1)?;
    let mut spool = b"good1\n".to_vec();
    spool.extend_from_slice(BAD_LINE);
    spool.extend_from_slice(b"good2\ntorn");
    fs::write(&file.spool_file, spool)?;
    let claimed = claim_spool(&file)?;
    assert_eq!(texts(&claimed.batches), vec!["good1".to_owned(), "good2".to_owned()]);
    assert!(fs::metadata(&rejected)?.len() < MAX_REJECTED_BYTES);
    let kept = fs::read_to_string(&rejected)?;
    assert!(kept.contains("torn"), "{kept}");
    Ok(())
}
