use crate::cursor::write_cursor;
use crate::error::SourceError;
use crate::model::{Cursor, Follower, Notes, Paths, Report, SourceSettings, StateDir, Stop};
use crate::spool::append_locked;
use crate::types::StepFn;
use core_export::ecs::to_json;
use ecs_normalise::convert::Outcome;
use ecs_normalise::stream::{decode, read_raw_line, RawLine};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::os::unix::fs::{FileExt, MetadataExt, OpenOptionsExt};
use std::path::Path;


const NEWLINE: u8 = b'\n';


/// One pass over the export file: the lines kept for the spool, the offset after the last consumed line and the counts.
#[derive(Debug)]
pub struct Pass {
    pub lines: Vec<String>,
    pub offset: u64,
    pub pending: u64,
    pub line_number: u64,
    pub skipping: bool,
    pub report: Report,
}


#[derive(Debug, Clone, Copy)]
pub struct PassContext<'a> {
    pub settings: &'a SourceSettings,
    pub line_limit: usize,
}


/// Opens the export file without following a symlink and without blocking on a FIFO; refuses anything but a regular file, judged on the open handle.
pub fn open_export(path: &Path) -> Result<File, SourceError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    if file.metadata()?.is_file() {
        Ok(file)
    } else {
        Err(SourceError::NotRegular(path.to_path_buf()))
    }
}


/// The persisted cursor when it names this very file (device and inode), otherwise the start of this file.
pub fn cursor_for(file: &File, persisted: Cursor) -> io::Result<Cursor> {
    let metadata = file.metadata()?;
    let same = metadata.dev() == persisted.dev && metadata.ino() == persisted.ino;
    Ok(if same {
        persisted
    } else {
        Cursor {
            dev: metadata.dev(),
            ino: metadata.ino(),
            offset: 0,
            skipping: false,
        }
    })
}


pub fn ends_with_newline(file: &File, position: u64) -> io::Result<bool> {
    let mut byte = [NEWLINE; 1];
    file.read_exact_at(&mut byte, position.saturating_sub(1))?;
    Ok(byte == [NEWLINE])
}


/// An offset is valid at the start of the file, or inside it right after a line end: a shorter file or a rewritten one shows as invalid.
pub fn offset_valid(file: &File, offset: u64) -> io::Result<bool> {
    let length = file.metadata()?.len();
    let inside = offset <= length;
    Ok(offset == 0 || (inside && ends_with_newline(file, offset)?))
}


/// The size of a file, zero when it does not exist.
pub fn file_len(path: &Path) -> io::Result<u64> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error),
    }
}


/// Opens the export file for a follower that holds none; a missing file is `None`, and the cursor follows the file actually opened.
pub fn open_current(path: &Path, cursor: &mut Cursor) -> Result<Option<File>, SourceError> {
    match open_export(path) {
        Ok(file) => {
            let persisted = *cursor;
            *cursor = cursor_for(&file, persisted)?;
            let replaced = persisted != Cursor::default() && (persisted.dev, persisted.ino) != (cursor.dev, cursor.ino);
            if replaced {
                let (old, new) = ((persisted.dev, persisted.ino), (cursor.dev, cursor.ino));
                tracing::warn!(?old, ?new, "export file replaced while not followed");
            }
            Ok(Some(file))
        }
        Err(SourceError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}


/// The file now at the export path when its identity is not the followed one, and whether the path is unusable (the old handle is then kept).
pub fn rotation_candidate(path: &Path, cursor: Cursor) -> Result<(Option<(File, Cursor)>, bool), SourceError> {
    match open_export(path) {
        Ok(next) => {
            let metadata = next.metadata()?;
            let same = metadata.dev() == cursor.dev && metadata.ino() == cursor.ino;
            let fresh = Cursor {
                dev: metadata.dev(),
                ino: metadata.ino(),
                offset: 0,
                skipping: false,
            };
            Ok((if same { None } else { Some((next, fresh)) }, false))
        }
        Err(SourceError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok((None, false)),
        Err(error) => {
            tracing::debug!(%error, "export path not usable");
            Ok((None, true))
        }
    }
}


fn fit(pass: Pass, json: String, offset: u64, context: &PassContext) -> Pass {
    if json.len() > context.line_limit {
        Pass {
            offset,
            report: Report {
                oversized: pass.report.oversized + 1,
                ..pass.report
            },
            ..pass
        }
    } else {
        let added = json.len() as u64 + 1;
        let mut lines = pass.lines;
        lines.push(json);
        Pass {
            lines,
            offset,
            pending: pass.pending + added,
            report: Report {
                spooled: pass.report.spooled + 1,
                ..pass.report
            },
            ..pass
        }
    }
}


/// Converts one complete line: an event is kept for the spool, an unknown kind or a malformed line is counted.
pub fn process_line(pass: Pass, bytes: Vec<u8>, offset: u64, context: &PassContext) -> Result<Pass, SourceError> {
    let line_number = pass.line_number + 1;
    let counted = Pass { line_number, ..pass };
    match decode(line_number, RawLine::Text(bytes), context.settings.max_line_bytes) {
        Ok(Outcome::Event(event)) => Ok(fit(counted, to_json(&event)?, offset, context)),
        Ok(Outcome::Unknown(_)) => Ok(Pass {
            offset,
            report: Report {
                unknown: counted.report.unknown + 1,
                ..counted.report
            },
            ..counted
        }),
        Err(_) => Ok(Pass {
            offset,
            report: Report {
                malformed: counted.report.malformed + 1,
                ..counted.report
            },
            ..counted
        }),
    }
}


pub fn read_step(reader: &mut BufReader<&File>, file: &File, pass: Pass, context: &PassContext) -> Result<Pass, SourceError> {
    if pass.report.stop != Stop::Running {
        Ok(pass)
    } else if pass.pending >= context.settings.max_spool_bytes {
        Ok(Pass {
            report: Report {
                stop: Stop::Full,
                ..pass.report
            },
            ..pass
        })
    } else {
        match read_raw_line(reader, context.settings.max_line_bytes)? {
            None => Ok(Pass {
                report: Report {
                    stop: Stop::Eof,
                    ..pass.report
                },
                ..pass
            }),
            Some(RawLine::TooLong) => {
                let end = reader.stream_position()?;
                let skipping = !ends_with_newline(file, end)?;
                Ok(Pass {
                    offset: end,
                    skipping,
                    line_number: pass.line_number + 1,
                    report: Report {
                        oversized: pass.report.oversized + 1,
                        stop: if skipping { Stop::Eof } else { Stop::Running },
                        ..pass.report
                    },
                    ..pass
                })
            }
            Some(RawLine::Text(bytes)) => {
                let end = reader.stream_position()?;
                if ends_with_newline(file, end)? {
                    process_line(pass, bytes, end, context)
                } else {
                    Ok(Pass {
                        report: Report {
                            stop: Stop::Partial,
                            ..pass.report
                        },
                        ..pass
                    })
                }
            }
        }
    }
}


/// Skips the rest of an overlong line the previous poll left half-skipped; true while its newline has not been reached.
pub fn skip_rest(reader: &mut BufReader<&File>, file: &File) -> io::Result<bool> {
    reader.skip_until(NEWLINE)?;
    let position = reader.stream_position()?;
    Ok(!ends_with_newline(file, position)?)
}


/// Reads the complete lines after the cursor. A cursor inside a skipped overlong line (`skipping`) first finishes skipping it and is never a truncation.
pub fn read_pass(file: &File, cursor: &Cursor, pending: u64, context: &PassContext) -> Result<Pass, SourceError> {
    let length = file.metadata()?.len();
    let resumed = cursor.skipping && cursor.offset <= length;
    let valid = resumed || offset_valid(file, cursor.offset)?;
    let start = if valid { cursor.offset } else { 0 };
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(start))?;
    let skipping = if resumed { skip_rest(&mut reader, file)? } else { false };
    let initial = Pass {
        lines: Vec::new(),
        offset: reader.stream_position()?,
        pending,
        line_number: 0,
        skipping,
        report: Report {
            truncated: !valid,
            stop: if skipping { Stop::Eof } else { Stop::Running },
            ..Report::default()
        },
    };
    (0..context.settings.max_lines_per_poll).try_fold(initial, |acc, _| read_step(&mut reader, file, acc, context))
}


/// Reads, appends the events to the spool, then moves the cursor (a crash between replays, never skips); a read failure is `Undrained`.
pub fn drain(file: &File, cursor: &mut Cursor, paths: &Paths, settings: &SourceSettings, line_limit: usize) -> Result<Report, SourceError> {
    let pending = file_len(&paths.spool)? + file_len(&paths.sending)?;
    let context = PassContext { settings, line_limit };
    let pass = read_pass(file, cursor, pending, &context).map_err(|error| SourceError::Undrained(Box::new(error)))?;
    append_locked(&paths.lock, pass.lines.into_iter().map(Ok::<String, io::Error>), &paths.spool)?;
    cursor.offset = pass.offset;
    cursor.skipping = pass.skipping;
    let stop = if pass.report.stop == Stop::Running {
        Stop::Capped
    } else {
        pass.report.stop
    };
    Ok(Report { stop, ..pass.report })
}


/// Writes the cursor when it differs from the last written one; returns the cursor now on disk.
pub fn save_if_changed(state: &StateDir, path: &Path, cursor: Cursor, saved: Cursor) -> Result<Cursor, SourceError> {
    if cursor == saved {
        Ok(saved)
    } else {
        write_cursor(state, path, cursor)?;
        Ok(cursor)
    }
}


fn log_report(report: &Report) {
    let Report {
        malformed,
        unknown,
        oversized,
        ..
    } = *report;
    if malformed + unknown + oversized > 0 {
        tracing::warn!(malformed, unknown, oversized, "export lines skipped");
    }
    if report.truncated {
        tracing::warn!("export file truncated or rewritten, read again from the start");
    }
}


/// Drains the followed file; when a rotation is pending, a read failure is counted and logged instead of blocking the switch (`true` in the pair).
pub fn drain_old(
    file: &File,
    cursor: &mut Cursor,
    paths: &Paths,
    settings: &SourceSettings,
    line_limit: usize,
    rotating: bool,
) -> Result<(Report, bool), SourceError> {
    match drain(file, cursor, paths, settings, line_limit) {
        Err(SourceError::Undrained(error)) if rotating => {
            tracing::warn!(%error, "old export file could not be drained, the rotation is followed and its last lines are lost");
            Ok((
                Report {
                    stop: Stop::Eof,
                    ..Report::default()
                },
                true,
            ))
        }
        other => Ok((other?, false)),
    }
}


/// Enters or leaves a state that is logged once per change: `Some(count)` is the polls spent in it when it ends, `None` otherwise.
pub fn track(polls: &mut u64, active: bool) -> (bool, Option<u64>) {
    let entered = active && *polls == 0;
    let left = if active || *polls == 0 { None } else { Some(*polls) };
    *polls = if active { *polls + 1 } else { 0 };
    (entered, left)
}


/// Logs the entry into and the exit from the spool-full and unusable-path states, with the number of polls each lasted.
pub fn log_states(notes: &mut Notes, full: bool, unusable: bool, pending: u64, limit: u64) {
    let (full_entered, full_left) = track(&mut notes.full_polls, full);
    let (unusable_entered, unusable_left) = track(&mut notes.unusable_polls, unusable);
    if full_entered {
        tracing::warn!(pending, limit, "spool full, reading paused");
    }
    if let Some(polls) = full_left {
        tracing::warn!(polls, "spool has room again, reading resumes");
    }
    if unusable_entered {
        tracing::warn!("export path not usable, the open file is kept");
    }
    if let Some(polls) = unusable_left {
        tracing::warn!(polls, "export path usable again");
    }
}


pub fn no_step(_paths: &Paths) {}


/// One poll with the production steps.
pub fn poll(follower: &mut Follower, state: &StateDir, paths: &Paths, settings: &SourceSettings, line_limit: usize) -> Result<Report, SourceError> {
    poll_stepped(follower, state, paths, settings, line_limit, no_step)
}


/// One poll: the new identity at the export path is detected first, `step` runs, the old file is drained to its end, then the follower switches.
pub fn poll_stepped(
    follower: &mut Follower,
    state: &StateDir,
    paths: &Paths,
    settings: &SourceSettings,
    line_limit: usize,
    step: StepFn,
) -> Result<Report, SourceError> {
    let Follower { cursor, current, notes } = follower;
    let mut unusable = false;
    let before = *cursor;
    if current.is_none() {
        *current = open_current(&paths.export, cursor)?;
    }
    let (report, replacement) = match current.as_ref() {
        None => (
            Report {
                missing: true,
                ..Report::default()
            },
            None,
        ),
        Some(file) => {
            let (next, blocked) = rotation_candidate(&paths.export, *cursor)?;
            unusable = blocked;
            step(paths);
            let (drained, undrained) = drain_old(file, cursor, paths, settings, line_limit, next.is_some())?;
            let saved = save_if_changed(state, &paths.cursor_file, *cursor, before)?;
            let follow = undrained || matches!(drained.stop, Stop::Eof | Stop::Partial);
            let switch = next.filter(|_| follow);
            if let Some((_, fresh)) = &switch {
                *cursor = *fresh;
            }
            save_if_changed(state, &paths.cursor_file, *cursor, saved)?;
            let lost = u64::from(switch.is_some() && drained.stop == Stop::Partial) + u64::from(undrained);
            (
                Report {
                    rotated: switch.is_some(),
                    malformed: drained.malformed + lost,
                    ..drained
                },
                switch.map(|(opened, _)| opened),
            )
        }
    };
    if let Some(next) = replacement {
        *current = Some(next);
    }
    log_report(&report);
    log_states(
        notes,
        report.stop == Stop::Full,
        unusable,
        file_len(&paths.spool)?,
        settings.max_spool_bytes,
    );
    Ok(report)
}
