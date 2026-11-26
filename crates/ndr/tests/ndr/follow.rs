use crate::support::{logging_on, now, TestResult};
use ndr::error::NdrError;
use ndr::follow::{
    cursor_of, digest_hex, drain, follow_tick, load_state, open_eve, open_state_dir, read_range, resume, store_state, switch, CHUNK_BYTES,
    MAX_CHUNKS, MAX_STATE_BYTES,
};
use ndr::model::{Cursor, Limits, TickOutcome};
use ndr::scan::{check_tick, holds_cursor, record_scan, validate_limits, MAX_LINE_BYTES_LIMIT};
use rustix::fs::{mknodat, FileType, Mode, CWD};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};


const SMALL_LINE: usize = 16;


const LONG_LINE: usize = 200_000;


const MANY_LINES: usize = 5_000;


const TWO: usize = 2;


const TICK_SKIP_BYTES: u64 = (CHUNK_BYTES * MAX_CHUNKS) as u64;


const HUGE_LINE: u64 = 300 * 1_048_576;


const TWO_GIB: u64 = 2 * 1_073_741_824;


const NEXT_TAIL_BYTES: u64 = 6;


const THREE: usize = 3;


const MODE_PRIVATE: u32 = 0o700;


const MODE_OPEN: u32 = 0o777;


const FIFO_MODE: u32 = 0o600;


const NAME_LENGTH: usize = 300;


const BIG_STATE: usize = 5_000;


const PAST_END: u64 = 10_000;


fn limits(lines: usize, line_bytes: usize) -> Limits {
    Limits {
        max_lines_per_tick: lines,
        max_line_bytes: line_bytes,
        ..Limits::default()
    }
}


fn text(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| (*item).to_string()).collect()
}


fn append(path: &Path, bytes: &[u8]) -> TestResult {
    OpenOptions::new().create(true).append(true).open(path)?.write_all(bytes)?;
    Ok(())
}


fn eve_in(dir: &Path) -> PathBuf {
    dir.join("eve.json")
}


fn private_dir() -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    let dir = tempfile::tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(MODE_PRIVATE))?;
    Ok(dir)
}


fn cursor_after(path: &Path, text: &[u8]) -> Result<Cursor, Box<dyn std::error::Error>> {
    fs::write(path, text)?;
    let (start, _) = resume(path, None, &Limits::default())?;
    let ticked = follow_tick(path, &start, &Limits::default())?;
    Ok(cursor_of(&ticked.follower)?)
}


#[test]
fn lines_are_returned_once_and_a_partial_line_waits_for_its_newline() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    fs::write(&path, "a\nb\nc")?;
    let (start, counts) = resume(&path, None, &Limits::default())?;
    assert_eq!(counts.rotated_while_down + counts.eve_truncated, 0);
    let first = follow_tick(&path, &start, &Limits::default())?;
    assert_eq!(first.lines, vec!["a", "b"]);
    assert_eq!(first.follower.offset, TWO as u64 * TWO as u64);
    append(&path, b"x\nd\n")?;
    let second = follow_tick(&path, &first.follower, &Limits::default())?;
    assert_eq!(second.lines, vec!["cx", "d"]);
    let third = follow_tick(&path, &second.follower, &Limits::default())?;
    assert!(third.lines.is_empty());
    assert_eq!(third.follower.offset, second.follower.offset);
    Ok(())
}


#[test]
fn a_tick_returns_at_most_the_line_budget_and_the_offset_follows_the_last_line() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    fs::write(&path, "1\n2\n3\n4\n5\n")?;
    let small = limits(TWO, Limits::default().max_line_bytes);
    let (start, _) = resume(&path, None, &small)?;
    let first = follow_tick(&path, &start, &small)?;
    let second = follow_tick(&path, &first.follower, &small)?;
    let third = follow_tick(&path, &second.follower, &small)?;
    assert_eq!(
        (first.lines, second.lines, third.lines),
        (text(&["1", "2"]), text(&["3", "4"]), text(&["5"]))
    );
    Ok(())
}


#[test]
fn a_file_larger_than_one_chunk_is_read_without_loss_across_chunk_boundaries() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    let text: String = (0..MANY_LINES).map(|index| format!("line-{index}-padding-padding\n")).collect();
    fs::write(&path, &text)?;
    let all = limits(MANY_LINES, Limits::default().max_line_bytes);
    let (start, _) = resume(&path, None, &all)?;
    let ticked = follow_tick(&path, &start, &all)?;
    assert_eq!(ticked.lines.len(), MANY_LINES);
    assert_eq!(ticked.lines.join("\n") + "\n", text);
    Ok(())
}


#[test]
fn invalid_utf8_and_over_long_lines_are_counted_malformed_and_skipped_alone() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    let mut bytes = b"ok1\n\xff\xfe\n".to_vec();
    bytes.extend(vec![b'x'; LONG_LINE]);
    bytes.extend(b"\nabcdefghijklmnopqrstuvwxyz\nok2\n");
    fs::write(&path, &bytes)?;
    let narrow = limits(MANY_LINES, SMALL_LINE);
    let (start, _) = resume(&path, None, &narrow)?;
    let ticked = follow_tick(&path, &start, &narrow)?;
    assert_eq!(ticked.lines, vec!["ok1", "ok2"]);
    assert_eq!(ticked.counts.malformed, THREE as u64);
    let again = follow_tick(&path, &ticked.follower, &narrow)?;
    assert_eq!((again.lines.len(), again.counts.eve_truncated), (0, 0));
    Ok(())
}


#[test]
fn an_over_long_line_still_being_written_is_not_counted_until_it_ends() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    fs::write(&path, "ok\n0123456789abcdefghij")?;
    let narrow = limits(MANY_LINES, SMALL_LINE);
    let (start, _) = resume(&path, None, &narrow)?;
    let first = follow_tick(&path, &start, &narrow)?;
    assert_eq!((first.lines.len(), first.counts.malformed), (1, 0));
    append(&path, b"klmnop\nnext\n")?;
    let second = follow_tick(&path, &first.follower, &narrow)?;
    assert_eq!((second.lines, second.counts.malformed), (vec!["next".to_string()], 1));
    Ok(())
}


#[test]
fn a_move_rotation_loses_and_repeats_nothing() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    fs::write(&path, "a\nb\n")?;
    let (start, _) = resume(&path, None, &Limits::default())?;
    let first = follow_tick(&path, &start, &Limits::default())?;
    append(&path, b"c\nd")?;
    fs::rename(&path, dir.path().join("eve.json.1"))?;
    let gap = follow_tick(&path, &first.follower, &Limits::default())?;
    assert_eq!((gap.lines.clone(), gap.counts.rotations), (vec!["c".to_string()], 0));
    fs::write(&path, "")?;
    let empty = follow_tick(&path, &gap.follower, &Limits::default())?;
    assert!(empty.lines.is_empty());
    append(&path, b"e\nf\n")?;
    let switched = follow_tick(&path, &empty.follower, &Limits::default())?;
    assert_eq!(
        (switched.lines, switched.counts.rotations, switched.counts.malformed),
        (text(&["e", "f"]), 1, 1)
    );
    let after = follow_tick(&path, &switched.follower, &Limits::default())?;
    assert!(after.lines.is_empty());
    Ok(())
}


#[test]
fn the_old_file_is_drained_a_last_time_when_lines_land_before_the_switch() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    fs::write(&path, "a\n")?;
    let (start, _) = resume(&path, None, &Limits::default())?;
    let first = follow_tick(&path, &start, &Limits::default())?;
    append(&path, b"late\n")?;
    fs::rename(&path, dir.path().join("eve.json.1"))?;
    fs::write(&path, "n1\n")?;
    let switched = follow_tick(&path, &first.follower, &Limits::default())?;
    assert_eq!((switched.lines, switched.counts.malformed), (text(&["late", "n1"]), 0));
    Ok(())
}


#[test]
fn a_rotated_path_that_is_absent_keeps_the_old_handle() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    fs::write(&path, "a\n")?;
    let (start, _) = resume(&path, None, &Limits::default())?;
    fs::rename(&path, dir.path().join("eve.json.1"))?;
    let ticked = follow_tick(&path, &start, &Limits::default())?;
    assert_eq!(ticked.lines, vec!["a"]);
    Ok(())
}


#[test]
fn the_switch_waits_while_the_old_file_still_holds_more_than_the_budget() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    fs::write(&path, "1\n2\n3\n")?;
    let (start, _) = resume(&path, None, &Limits::default())?;
    let idle = drain(&start.clone(), 0, &Limits::default())?;
    assert!(!idle.eof);
    fs::rename(&path, dir.path().join("eve.json.1"))?;
    fs::write(&path, "n\n")?;
    let next = open_eve(&path)?.ok_or("absent")?;
    let held = switch(idle, next, &limits(1, Limits::default().max_line_bytes), u64::MAX)?;
    assert_eq!((held.lines, held.counts.rotations, held.eof), (vec!["1".to_string()], 0, false));
    Ok(())
}


#[test]
fn a_follower_that_was_not_committed_can_retry_its_tick() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    fs::write(&path, "a\nb\n")?;
    let (start, _) = resume(&path, None, &Limits::default())?;
    let first = follow_tick(&path, &start, &Limits::default())?;
    let retry = follow_tick(&path, &start, &Limits::default())?;
    assert_eq!((first.lines, retry.lines), (text(&["a", "b"]), text(&["a", "b"])));
    Ok(())
}


#[test]
fn a_copytruncate_is_named_and_read_from_the_start() -> TestResult {
    assert!(logging_on());
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    fs::write(&path, "aaaa\nbbbb\n")?;
    let (start, _) = resume(&path, None, &Limits::default())?;
    let first = follow_tick(&path, &start, &Limits::default())?;
    File::options().write(true).open(&path)?.set_len(0)?;
    append(&path, b"cc\n")?;
    let second = follow_tick(&path, &first.follower, &Limits::default())?;
    assert_eq!((second.lines.clone(), second.counts.eve_truncated), (vec!["cc".to_string()], 1));
    fs::write(&path, "dddddddddd\neeeeeeeeee\n")?;
    let third = follow_tick(&path, &second.follower, &Limits::default())?;
    assert_eq!((third.lines, third.counts.eve_truncated), (text(&["dddddddddd", "eeeeeeeeee"]), 1));
    Ok(())
}


#[test]
fn a_cursor_resumes_where_it_stopped_and_names_every_gap() -> TestResult {
    assert!(logging_on());
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    let cursor = cursor_after(&path, b"first line\nsecond line\n")?;
    append(&path, b"third\n")?;
    let (follower, counts) = resume(&path, Some(&cursor), &Limits::default())?;
    assert_eq!(
        (follower.offset, counts.eve_truncated + counts.rotated_while_down + counts.device_changed),
        (cursor.offset, 0)
    );
    let ticked = follow_tick(&path, &follower, &Limits::default())?;
    assert_eq!(ticked.lines, vec!["third"]);

    let moved = Cursor {
        device: cursor.device + 1,
        ..cursor.clone()
    };
    let (_, device_counts) = resume(&path, Some(&moved), &Limits::default())?;
    assert_eq!((device_counts.device_changed, device_counts.eve_truncated), (1, 0));

    let wrong_head = Cursor {
        head_sha256: digest_hex(b"other"),
        ..cursor.clone()
    };
    let (rewound, head_counts) = resume(&path, Some(&wrong_head), &Limits::default())?;
    assert_eq!((rewound.offset, head_counts.eve_truncated), (0, 1));

    let wrong_tail = Cursor {
        tail_sha256: digest_hex(b"other"),
        ..cursor.clone()
    };
    let (_, tail_counts) = resume(&path, Some(&wrong_tail), &Limits::default())?;
    assert_eq!(tail_counts.eve_truncated, 1);

    let past = Cursor {
        offset: PAST_END,
        head_len: ndr::follow::HEAD_BYTES,
        ..cursor.clone()
    };
    let (_, short_counts) = resume(&path, Some(&past), &Limits::default())?;
    assert_eq!(short_counts.eve_truncated, 1);

    fs::rename(&path, dir.path().join("old"))?;
    fs::write(&path, "first line\nsecond line\n")?;
    let (replaced, replaced_counts) = resume(&path, Some(&cursor), &Limits::default())?;
    assert_eq!((replaced.offset, replaced_counts.rotated_while_down), (0, 1));
    Ok(())
}


#[test]
fn an_impossible_cursor_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    let cursor = cursor_after(&path, b"first line\nsecond line\n")?;
    let bad = [
        Cursor {
            head_len: cursor.head_len + 1,
            ..cursor.clone()
        },
        Cursor {
            tail_len: cursor.offset as usize + 1,
            ..cursor.clone()
        },
        Cursor {
            tail_len: Limits::default().max_line_bytes + 1,
            offset: u64::MAX,
            head_len: ndr::follow::HEAD_BYTES,
            ..cursor.clone()
        },
        Cursor {
            tail_len: 0,
            ..cursor.clone()
        },
    ];
    bad.iter()
        .try_for_each(|candidate| match resume(&path, Some(candidate), &Limits::default()) {
            Err(NdrError::CursorInvalid) => Ok(()),
            _ => Err("accepted"),
        })?;
    Ok(())
}


#[test]
fn a_cursor_of_a_file_that_shrank_cannot_be_built() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    let cursor_start = cursor_after(&path, b"first line\n")?;
    assert_eq!(cursor_start.head_len as u64, cursor_start.offset);
    let (follower, _) = resume(&path, None, &Limits::default())?;
    let ticked = follow_tick(&path, &follower, &Limits::default())?;
    File::options().write(true).open(&path)?.set_len(1)?;
    assert!(cursor_of(&ticked.follower).is_err());
    Ok(())
}


#[test]
fn eve_json_must_be_a_regular_file_never_a_link_or_a_pipe() -> TestResult {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("target");
    fs::write(&target, "a\n")?;
    let link = dir.path().join("link");
    symlink(&target, &link)?;
    assert!(matches!(open_eve(&link), Err(NdrError::EveNotRegular)));
    let fifo = dir.path().join("fifo");
    mknodat(CWD, &fifo, FileType::Fifo, Mode::from_raw_mode(FIFO_MODE), 0)?;
    assert!(matches!(open_eve(&fifo), Err(NdrError::EveNotRegular)));
    assert!(matches!(open_eve(&target.join("below")), Err(NdrError::Eve(_))));
    assert!(open_eve(&dir.path().join("absent"))?.is_none());
    assert!(matches!(
        resume(&dir.path().join("absent"), None, &Limits::default()),
        Err(NdrError::EveMissing)
    ));
    Ok(())
}


#[test]
fn a_read_error_is_returned_and_a_short_file_is_none() -> TestResult {
    let dir = tempfile::tempdir()?;
    let directory = File::open(dir.path())?;
    assert!(read_range(&directory, 0, 1).is_err());
    let path = dir.path().join("f");
    fs::write(&path, "ab")?;
    assert!(read_range(&File::open(&path)?, 0, THREE)?.is_none());
    Ok(())
}


#[test]
fn the_state_round_trips_and_an_absent_state_is_none() -> TestResult {
    let dir = private_dir()?;
    let handle = open_state_dir(dir.path())?;
    assert!(load_state(&handle, "state.json")?.is_none());
    let eve = dir.path().join("eve.json");
    let cursor = cursor_after(&eve, b"one\ntwo\n")?;
    store_state(&handle, "state.json.tmp", "state.json", &cursor)?;
    store_state(&handle, "state.json.tmp", "state.json", &cursor)?;
    assert_eq!(load_state(&handle, "state.json")?, Some(cursor));
    assert!(!dir.path().join("state.json.tmp").exists());
    Ok(())
}


#[test]
fn a_bad_state_file_is_a_named_error_never_a_reset() -> TestResult {
    assert!(logging_on());
    let dir = private_dir()?;
    let handle = open_state_dir(dir.path())?;
    fs::write(dir.path().join("garbage"), "not json")?;
    assert!(matches!(load_state(&handle, "garbage"), Err(NdrError::StateMalformed)));
    fs::write(
        dir.path().join("extra"),
        r#"{"inode":1,"device":1,"head_len":0,"head_sha256":"","offset":0,"tail_len":0,"tail_sha256":"","x":1}"#,
    )?;
    assert!(matches!(load_state(&handle, "extra"), Err(NdrError::StateMalformed)));
    fs::write(dir.path().join("big"), vec![b' '; BIG_STATE])?;
    assert!(matches!(
        load_state(&handle, "big"),
        Err(NdrError::StateTooLarge { max_bytes: MAX_STATE_BYTES })
    ));
    symlink(dir.path().join("garbage"), dir.path().join("link"))?;
    assert!(matches!(load_state(&handle, "link"), Err(NdrError::StateNotRegular)));
    mknodat(CWD, dir.path().join("fifo"), FileType::Fifo, Mode::from_raw_mode(FIFO_MODE), 0)?;
    assert!(matches!(load_state(&handle, "fifo"), Err(NdrError::StateNotRegular)));
    assert!(matches!(load_state(&handle, &"n".repeat(NAME_LENGTH)), Err(NdrError::State(_))));
    Ok(())
}


#[test]
fn a_state_write_that_cannot_complete_is_an_error_and_keeps_the_old_state() -> TestResult {
    let dir = private_dir()?;
    let handle = open_state_dir(dir.path())?;
    let eve = dir.path().join("eve.json");
    let cursor = cursor_after(&eve, b"one\n")?;
    store_state(&handle, "tmp", "state", &cursor)?;
    fs::create_dir(dir.path().join("tmpdir"))?;
    assert!(matches!(store_state(&handle, "tmpdir", "state", &cursor), Err(NdrError::State(_))));
    fs::create_dir(dir.path().join("target"))?;
    fs::write(dir.path().join("target").join("inner"), "x")?;
    assert!(matches!(store_state(&handle, "tmp", "target", &cursor), Err(NdrError::State(_))));
    assert_eq!(load_state(&handle, "state")?, Some(cursor.clone()));
    let gone = private_dir()?;
    let orphan = open_state_dir(gone.path())?;
    let moved = gone.path().with_extension("moved");
    fs::rename(gone.path(), &moved)?;
    fs::remove_dir(&moved)?;
    assert!(matches!(store_state(&orphan, "tmp", "state", &cursor), Err(NdrError::State(_))));
    Ok(())
}


#[test]
fn a_state_directory_open_to_others_is_refused() -> TestResult {
    let dir = tempfile::tempdir()?;
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(MODE_OPEN))?;
    assert!(matches!(open_state_dir(dir.path()), Err(NdrError::WorkDir(_))));
    Ok(())
}


#[test]
fn the_state_directory_listing_names_a_directory_as_state_not_regular() -> TestResult {
    let dir = private_dir()?;
    let handle = open_state_dir(dir.path())?;
    fs::create_dir(dir.path().join("sub"))?;
    assert!(matches!(load_state(&handle, "sub"), Err(NdrError::StateNotRegular)));
    Ok(())
}


#[test]
fn environment_errors_are_counted_apart_and_hold_the_cursor() -> TestResult {
    assert!(logging_on());
    let mut outcome = TickOutcome::default();
    let failures = [
        NdrError::Output(std::io::Error::other("injected")),
        NdrError::Workspace(std::io::Error::other("injected")),
        NdrError::Spawn(std::io::Error::other("injected")),
        NdrError::Program {
            path: "yr".into(),
            reason: "injected",
        },
    ];
    failures
        .into_iter()
        .for_each(|failure| record_scan(&mut outcome, Err(failure), &[], 0, now()));
    assert_eq!((outcome.counts.failed, outcome.counts.run_refused), (1, THREE as u64));
    assert!(holds_cursor(&outcome));
    Ok(())
}


#[test]
fn limits_that_could_defer_are_refused_and_a_deferral_is_a_named_error() -> TestResult {
    let tight = Limits {
        max_lines_per_tick: THREE,
        max_files_per_tick: TWO,
        ..Limits::default()
    };
    assert!(matches!(validate_limits(&tight), Err(NdrError::Limits { .. })));
    assert!(validate_limits(&Limits::default()).is_ok());
    let mut outcome = TickOutcome::default();
    assert!(check_tick(&outcome).is_ok());
    assert!(!holds_cursor(&outcome));
    outcome.counts.deferred = 1;
    assert!(matches!(check_tick(&outcome), Err(NdrError::Deferred { count: 1 })));
    assert!(holds_cursor(&outcome));
    Ok(())
}


fn sparse_line(path: &Path, bytes: u64) -> TestResult {
    File::create(path)?.set_len(bytes)?;
    Ok(())
}


#[test]
fn a_line_longer_than_one_tick_budget_is_skipped_across_ticks_and_counted_once() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    sparse_line(&path, HUGE_LINE)?;
    let (start, _) = resume(&path, None, &Limits::default())?;
    let first = follow_tick(&path, &start, &Limits::default())?;
    assert_eq!((first.lines.len(), first.counts.malformed, first.skipping_bytes), (0, 0, TICK_SKIP_BYTES));
    let second = follow_tick(&path, &first.follower, &Limits::default())?;
    assert_eq!((second.lines.len(), second.skipping_bytes), (0, HUGE_LINE));
    append(&path, b"\nnext\n")?;
    let third = follow_tick(&path, &second.follower, &Limits::default())?;
    assert_eq!((third.lines, third.counts.malformed, third.skipping_bytes), (text(&["next"]), 1, 0));
    assert_eq!(third.follower.offset, HUGE_LINE + NEXT_TAIL_BYTES);
    Ok(())
}


#[test]
fn a_rotation_during_a_skip_is_followed_and_the_old_tail_is_counted() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    sparse_line(&path, HUGE_LINE)?;
    let (start, _) = resume(&path, None, &Limits::default())?;
    let first = follow_tick(&path, &start, &Limits::default())?;
    assert_eq!(first.skipping_bytes, TICK_SKIP_BYTES);
    fs::rename(&path, dir.path().join("eve.json.1"))?;
    fs::write(&path, "n\n")?;
    let second = follow_tick(&path, &first.follower, &Limits::default())?;
    assert_eq!((second.lines, second.counts.rotations, second.counts.malformed), (text(&["n"]), 1, 1));
    assert_eq!(second.counts.rotated_unread_bytes, 0);
    Ok(())
}


#[test]
fn a_rotated_file_with_a_huge_unread_backlog_is_left_and_the_bytes_are_named() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    sparse_line(&path, TWO_GIB)?;
    let (start, _) = resume(&path, None, &Limits::default())?;
    fs::rename(&path, dir.path().join("eve.json.1"))?;
    fs::write(&path, "n\n")?;
    let ticked = follow_tick(&path, &start, &Limits::default())?;
    assert_eq!((ticked.lines, ticked.counts.rotations, ticked.counts.malformed), (text(&["n"]), 1, 0));
    assert_eq!(ticked.counts.rotated_unread_bytes, TWO_GIB - TWO as u64 * TICK_SKIP_BYTES);
    Ok(())
}


#[test]
fn a_small_backlog_cap_forces_the_switch_and_names_what_was_left() -> TestResult {
    let dir = tempfile::tempdir()?;
    let path = eve_in(dir.path());
    fs::write(&path, "1\n2\n3\n")?;
    let (start, _) = resume(&path, None, &Limits::default())?;
    let idle = drain(&start.clone(), 0, &Limits::default())?;
    fs::rename(&path, dir.path().join("eve.json.1"))?;
    fs::write(&path, "n\n")?;
    let next = open_eve(&path)?.ok_or("absent")?;
    let forced = switch(idle, next, &limits(1, Limits::default().max_line_bytes), 1)?;
    assert_eq!(
        (forced.lines, forced.counts.rotations, forced.counts.rotated_unread_bytes),
        (text(&["1"]), 1, TWO as u64 * TWO as u64)
    );
    Ok(())
}


#[test]
fn a_hard_linked_eve_json_is_refused_by_name() -> TestResult {
    let dir = tempfile::tempdir()?;
    let target = dir.path().join("target");
    fs::write(&target, "a\n")?;
    let path = eve_in(dir.path());
    fs::hard_link(&target, &path)?;
    assert!(matches!(open_eve(&path), Err(NdrError::EveShared)));
    assert!(matches!(resume(&path, None, &Limits::default()), Err(NdrError::EveShared)));
    Ok(())
}


#[test]
fn a_line_bound_above_the_upper_limit_is_refused() -> TestResult {
    let wide = Limits {
        max_line_bytes: MAX_LINE_BYTES_LIMIT + 1,
        ..Limits::default()
    };
    assert!(matches!(validate_limits(&wide), Err(NdrError::Limits { .. })));
    let edge = Limits {
        max_line_bytes: MAX_LINE_BYTES_LIMIT,
        ..Limits::default()
    };
    assert!(validate_limits(&edge).is_ok());
    Ok(())
}
