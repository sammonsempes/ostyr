use crate::support::{
    append, lines, poll_default, poll_with, scoped_logging, setup, EXEC, EXTRA_BYTES, FOREIGN_TENANT, LEN_FIVE, LEN_THREE, LEN_TWO, LINE_LIMIT,
    OVERLONG_BYTES, SMALL_LINE_BYTES, TINY_LINE_LIMIT, TWO, UNKNOWN, UNRELATED_OFFSET,
};
use crate::types::TestResult;
use agent_linux::cursor::{read_cursor, write_cursor};
use agent_linux::error::SourceError;
use agent_linux::follow::{file_len, open_export, poll_stepped};
use agent_linux::model::{Cursor, Follower, Paths, SourceSettings, Stop};
use std::fs;
use std::os::unix::fs::{symlink, MetadataExt};
use std::process::Command;


#[test]
fn lines_appended_are_spooled_once_as_ecs() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n{EXEC}\n"))?;
    let first = poll_default(&mut setup)?;
    assert_eq!((first.spooled, first.stop), (TWO, Stop::Eof));
    assert_eq!(poll_default(&mut setup)?.spooled, 0);
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    let spooled = lines(&setup.paths.spool)?;
    assert_eq!(spooled.len(), LEN_THREE);
    assert!(spooled.iter().all(|line| line.contains("tetragon") && line.contains("/usr/bin/curl")));
    assert_eq!(read_cursor(&setup.paths.cursor_file)?.offset, fs::metadata(&setup.paths.export)?.len());
    Ok(())
}


#[test]
fn the_tenant_is_never_taken_from_the_event() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{FOREIGN_TENANT}\n"))?;
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    assert!(!fs::read_to_string(&setup.paths.spool)?.contains("other"));
    Ok(())
}


#[test]
fn a_restart_neither_replays_nor_skips() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n{EXEC}\n"))?;
    assert_eq!(poll_default(&mut setup)?.spooled, TWO);
    setup.follower = Follower {
        cursor: read_cursor(&setup.paths.cursor_file)?,
        current: None,
    };
    assert_eq!(poll_default(&mut setup)?.spooled, 0);
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    setup.follower = Follower {
        cursor: read_cursor(&setup.paths.cursor_file)?,
        current: None,
    };
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    assert_eq!(lines(&setup.paths.spool)?.len(), LEN_THREE);
    Ok(())
}


#[test]
fn a_cursor_naming_another_file_starts_at_the_beginning() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n{EXEC}\n"))?;
    write_cursor(
        &setup.paths.cursor_file,
        Cursor {
            dev: 1,
            ino: 1,
            offset: UNRELATED_OFFSET,
            skipping: false,
        },
    )?;
    setup.follower = Follower {
        cursor: read_cursor(&setup.paths.cursor_file)?,
        current: None,
    };
    assert_eq!(poll_default(&mut setup)?.spooled, TWO);
    Ok(())
}


#[test]
fn a_rotation_drains_the_old_file_then_follows_the_new_one() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n{EXEC}\n"))?;
    assert_eq!(poll_default(&mut setup)?.spooled, TWO);
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    fs::rename(&setup.paths.export, setup.dir.path().join("export.json.1"))?;
    append(&setup.paths.export, &format!("{EXEC}\n{EXEC}\n"))?;
    let rotated = poll_default(&mut setup)?;
    assert_eq!((rotated.spooled, rotated.rotated), (1, true));
    let after = poll_default(&mut setup)?;
    assert_eq!((after.spooled, after.rotated), (TWO, false));
    assert_eq!(lines(&setup.paths.spool)?.len(), LEN_FIVE);
    assert_eq!(read_cursor(&setup.paths.cursor_file)?.ino, fs::metadata(&setup.paths.export)?.ino());
    Ok(())
}


#[test]
fn a_partial_line_of_a_rotated_file_is_counted_lost() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    append(&setup.paths.export, "{\"process_exec\":")?;
    fs::rename(&setup.paths.export, setup.dir.path().join("export.json.1"))?;
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    let rotated = poll_default(&mut setup)?;
    assert_eq!((rotated.malformed, rotated.rotated, rotated.stop), (1, true, Stop::Partial));
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    Ok(())
}


#[test]
fn a_truncated_file_is_read_again_from_the_start() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n{EXEC}\n"))?;
    assert_eq!(poll_default(&mut setup)?.spooled, TWO);
    fs::write(&setup.paths.export, format!("{EXEC}\n"))?;
    let truncated = poll_default(&mut setup)?;
    assert_eq!((truncated.truncated, truncated.spooled), (true, 1));
    Ok(())
}


#[test]
fn a_rewritten_file_is_never_read_from_the_middle_of_a_line() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    fs::write(&setup.paths.export, format!("{}\n", "x".repeat(EXEC.len() + EXTRA_BYTES)))?;
    let rewritten = poll_default(&mut setup)?;
    assert_eq!((rewritten.truncated, rewritten.malformed, rewritten.spooled), (true, 1, 0));
    Ok(())
}


#[test]
fn a_missing_export_file_is_waited_for() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    assert!(poll_default(&mut setup)?.missing);
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    let found = poll_default(&mut setup)?;
    assert_eq!((found.missing, found.spooled), (false, 1));
    Ok(())
}


#[test]
fn a_symlink_is_refused_and_a_fifo_never_blocks() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    let target = setup.dir.path().join("target");
    append(&target, &format!("{EXEC}\n"))?;
    symlink(&target, &setup.paths.export)?;
    assert!(matches!(poll_default(&mut setup), Err(error) if error.to_string().contains("input or output")));
    fs::remove_file(&setup.paths.export)?;
    assert!(Command::new("mkfifo").arg(&setup.paths.export).status()?.success());
    assert!(matches!(open_export(&setup.paths.export), Err(SourceError::NotRegular(_))));
    assert!(poll_default(&mut setup).is_err());
    assert!(!setup.paths.spool.exists());
    Ok(())
}


#[test]
fn an_unusable_path_after_a_rotation_keeps_the_open_file() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    let aside = setup.dir.path().join("export.json.1");
    fs::rename(&setup.paths.export, &aside)?;
    symlink(&aside, &setup.paths.export)?;
    assert!(!poll_default(&mut setup)?.rotated);
    append(&aside, &format!("{EXEC}\n"))?;
    fs::remove_file(&setup.paths.export)?;
    let gone = poll_default(&mut setup)?;
    assert_eq!((gone.spooled, gone.rotated), (1, false));
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    assert!(poll_default(&mut setup)?.rotated);
    Ok(())
}


#[test]
fn overlong_malformed_and_unknown_lines_are_counted() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    let settings = SourceSettings {
        max_line_bytes: SMALL_LINE_BYTES,
        ..SourceSettings::default()
    };
    let text = format!("{}\n{EXEC}\nnot json\n{UNKNOWN}\n", "x".repeat(OVERLONG_BYTES));
    append(&setup.paths.export, &text)?;
    let report = poll_with(&mut setup, &settings, LINE_LIMIT)?;
    assert_eq!((report.oversized, report.malformed, report.unknown, report.spooled), (1, 1, 1, 1));
    append(&setup.paths.export, &"y".repeat(OVERLONG_BYTES))?;
    let unterminated = poll_with(&mut setup, &settings, LINE_LIMIT)?;
    assert_eq!(unterminated.oversized, 1);
    Ok(())
}


#[test]
fn an_event_too_big_for_a_batch_is_counted_not_spooled() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    let report = poll_with(&mut setup, &SourceSettings::default(), TINY_LINE_LIMIT)?;
    assert_eq!((report.oversized, report.spooled), (1, 0));
    assert!(!setup.paths.spool.exists());
    assert_eq!(poll_with(&mut setup, &SourceSettings::default(), TINY_LINE_LIMIT)?.oversized, 0);
    Ok(())
}


#[test]
fn a_full_spool_stops_the_reader_and_it_resumes_when_space_frees() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    let settings = SourceSettings {
        max_spool_bytes: 1,
        ..SourceSettings::default()
    };
    append(&setup.paths.export, &format!("{EXEC}\n{EXEC}\n{EXEC}\n"))?;
    let first = poll_with(&mut setup, &settings, LINE_LIMIT)?;
    assert_eq!((first.spooled, first.stop), (1, Stop::Full));
    let offset = read_cursor(&setup.paths.cursor_file)?.offset;
    let blocked = poll_with(&mut setup, &settings, LINE_LIMIT)?;
    assert_eq!((blocked.spooled, blocked.stop), (0, Stop::Full));
    assert_eq!(read_cursor(&setup.paths.cursor_file)?.offset, offset);
    fs::rename(&setup.paths.spool, &setup.paths.sending)?;
    assert_eq!(poll_with(&mut setup, &settings, LINE_LIMIT)?.spooled, 0);
    fs::remove_file(&setup.paths.sending)?;
    assert_eq!(poll_with(&mut setup, &settings, LINE_LIMIT)?.spooled, 1);
    fs::remove_file(&setup.paths.spool)?;
    assert_eq!(poll_with(&mut setup, &settings, LINE_LIMIT)?.spooled, 1);
    Ok(())
}


#[test]
fn a_poll_reads_at_most_the_configured_lines() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    let settings = SourceSettings {
        max_lines_per_poll: 1,
        ..SourceSettings::default()
    };
    append(&setup.paths.export, &format!("{EXEC}\n{EXEC}\n"))?;
    let report = poll_with(&mut setup, &settings, LINE_LIMIT)?;
    assert_eq!((report.spooled, report.stop), (1, Stop::Capped));
    Ok(())
}


#[test]
fn a_partial_line_waits_for_its_end() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, EXEC)?;
    let waiting = poll_default(&mut setup)?;
    assert_eq!((waiting.spooled, waiting.stop), (0, Stop::Partial));
    append(&setup.paths.export, "\n")?;
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    Ok(())
}


#[test]
fn a_failed_spool_write_does_not_advance_the_offset() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    let good = setup.paths.spool.clone();
    setup.paths.spool = setup.dir.path().join("absent").join("spool");
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    assert!(poll_default(&mut setup).is_err());
    assert_eq!(setup.follower.cursor.offset, 0);
    setup.paths.spool = good;
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    Ok(())
}


#[test]
fn a_failed_cursor_write_is_an_error_and_the_lines_stay_spooled() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    setup.paths.cursor_file = setup.dir.path().join("absent").join("cursor");
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    assert!(poll_default(&mut setup).is_err());
    assert_eq!(lines(&setup.paths.spool)?.len(), 1);
    Ok(())
}


#[test]
fn a_file_length_error_other_than_not_found_is_reported() -> TestResult {
    let setup = setup()?;
    let blocked = setup.dir.path().join("plain");
    fs::write(&blocked, "x")?;
    assert!(file_len(&blocked.join("inside")).is_err());
    assert_eq!(file_len(&setup.dir.path().join("absent"))?, 0);
    Ok(())
}


const HUGE_LINE_BYTES: u64 = 268_435_456;


#[test]
fn a_huge_line_without_a_newline_is_skipped_not_buffered() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    fs::File::create(&setup.paths.export)?.set_len(HUGE_LINE_BYTES)?;
    let report = poll_default(&mut setup)?;
    assert_eq!((report.oversized, report.spooled), (1, 0));
    assert_eq!(read_cursor(&setup.paths.cursor_file)?.offset, HUGE_LINE_BYTES);
    Ok(())
}


const POLLS: usize = 4;


fn small_settings() -> SourceSettings {
    SourceSettings {
        max_line_bytes: SMALL_LINE_BYTES,
        ..SourceSettings::default()
    }
}


#[test]
fn an_unterminated_overlong_line_is_skipped_once_and_never_replays_the_file() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    let settings = small_settings();
    append(&setup.paths.export, &format!("{EXEC}\n{EXEC}\n{}", "x".repeat(OVERLONG_BYTES)))?;
    let reports = (0..POLLS)
        .map(|_| poll_with(&mut setup, &settings, LINE_LIMIT))
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(reports.iter().map(|report| report.spooled).sum::<u64>(), TWO);
    assert_eq!(reports.iter().map(|report| report.oversized).sum::<u64>(), 1);
    assert!(reports.iter().all(|report| !report.truncated));
    assert_eq!(lines(&setup.paths.spool)?.len(), LEN_TWO);
    assert!(read_cursor(&setup.paths.cursor_file)?.skipping);
    append(&setup.paths.export, &"y".repeat(OVERLONG_BYTES))?;
    setup.follower = Follower {
        cursor: read_cursor(&setup.paths.cursor_file)?,
        current: None,
    };
    let still = poll_with(&mut setup, &settings, LINE_LIMIT)?;
    assert_eq!((still.oversized, still.spooled, still.truncated), (0, 0, false));
    append(&setup.paths.export, &format!("tail\n{EXEC}\n"))?;
    let resumed = poll_with(&mut setup, &settings, LINE_LIMIT)?;
    assert_eq!(
        (resumed.spooled, resumed.oversized, resumed.malformed, resumed.truncated),
        (1, 0, 0, false)
    );
    assert!(!read_cursor(&setup.paths.cursor_file)?.skipping);
    assert_eq!(lines(&setup.paths.spool)?.len(), LEN_THREE);
    Ok(())
}


#[test]
fn a_file_rewritten_while_skipping_is_read_again_from_the_start() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    let settings = small_settings();
    append(&setup.paths.export, &"x".repeat(OVERLONG_BYTES))?;
    assert_eq!(poll_with(&mut setup, &settings, LINE_LIMIT)?.oversized, 1);
    fs::write(&setup.paths.export, format!("{EXEC}\n"))?;
    let rewritten = poll_with(&mut setup, &settings, LINE_LIMIT)?;
    assert_eq!((rewritten.truncated, rewritten.spooled), (true, 1));
    assert!(!setup.follower.cursor.skipping);
    Ok(())
}


fn append_to_old(paths: &Paths) {
    append(&paths.export.with_file_name("export.json.1"), &format!("{EXEC}\n"))
        .inspect_err(|error| tracing::warn!(%error, "test step failed"))
        .ok();
}


#[test]
fn lines_written_to_the_old_file_after_the_rotation_is_seen_are_drained_before_the_switch() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    fs::rename(&setup.paths.export, setup.dir.path().join("export.json.1"))?;
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    let rotated = poll_stepped(&mut setup.follower, &setup.paths, &SourceSettings::default(), LINE_LIMIT, append_to_old)?;
    assert_eq!((rotated.spooled, rotated.rotated), (1, true));
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    assert_eq!(lines(&setup.paths.spool)?.len(), LEN_THREE);
    Ok(())
}


#[test]
fn an_old_file_that_cannot_be_read_is_counted_and_the_rotation_is_followed() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    append(&setup.paths.export, &format!("{EXEC}\n"))?;
    setup.follower.current = Some(fs::File::open(setup.dir.path())?);
    let rotated = poll_default(&mut setup)?;
    assert_eq!((rotated.rotated, rotated.malformed, rotated.spooled), (true, 1, 0));
    assert_eq!(poll_default(&mut setup)?.spooled, 1);
    Ok(())
}


#[test]
fn an_unreadable_file_without_a_rotation_is_an_error() -> TestResult {
    let _log = scoped_logging();
    let mut setup = setup()?;
    setup.follower.current = Some(fs::File::open(setup.dir.path())?);
    assert!(matches!(poll_default(&mut setup), Err(error) if error.to_string().contains("could not be read")));
    Ok(())
}
