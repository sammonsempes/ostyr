use crate::cursor::write_cursor;
use crate::error::SourceError;
use crate::model::{Cursor, Follower, Paths, Report, SourceSettings, Stop};
use agent_channel::spool::append_back;
use core_export::ecs::to_json;
use ecs_normalise::convert::Outcome;
use ecs_normalise::stream::{decode, read_raw_line, RawLine};
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufReader, Seek, SeekFrom};
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
            *cursor = cursor_for(&file, *cursor)?;
            Ok(Some(file))
        }
        Err(SourceError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error),
    }
}


/// The file now at the export path when it is not the one followed (the new cursor is its start); an unusable path keeps the old handle.
pub fn rotated_file(path: &Path, cursor: &mut Cursor) -> Result<Option<File>, SourceError> {
    match open_export(path) {
        Ok(next) => {
            let candidate = cursor_for(&next, *cursor)?;
            if candidate == *cursor {
                Ok(None)
            } else {
                *cursor = candidate;
                Ok(Some(next))
            }
        }
        Err(SourceError::Io(error)) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => {
            tracing::warn!(%error, "export path not usable, the open file is kept");
            Ok(None)
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
            Some(RawLine::TooLong) => Ok(Pass {
                offset: reader.stream_position()?,
                line_number: pass.line_number + 1,
                report: Report {
                    oversized: pass.report.oversized + 1,
                    ..pass.report
                },
                ..pass
            }),
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


/// Reads the complete lines after the cursor, appends the events to the spool, then moves the cursor offset: a crash between the two replays, never skips.
pub fn drain(file: &File, cursor: &mut Cursor, paths: &Paths, settings: &SourceSettings, line_limit: usize) -> Result<Report, SourceError> {
    let valid = offset_valid(file, cursor.offset)?;
    let start = if valid { cursor.offset } else { 0 };
    let pending = file_len(&paths.spool)? + file_len(&paths.sending)?;
    let mut reader = BufReader::new(file);
    reader.seek(SeekFrom::Start(start))?;
    let initial = Pass {
        lines: Vec::new(),
        offset: start,
        pending,
        line_number: 0,
        report: Report {
            truncated: !valid,
            ..Report::default()
        },
    };
    let context = PassContext { settings, line_limit };
    let pass = (0..settings.max_lines_per_poll).try_fold(initial, |acc, _| read_step(&mut reader, file, acc, &context))?;
    append_back(pass.lines.into_iter().map(Ok::<String, io::Error>), &paths.spool)?;
    cursor.offset = pass.offset;
    let stop = if pass.report.stop == Stop::Running {
        Stop::Capped
    } else {
        pass.report.stop
    };
    Ok(Report { stop, ..pass.report })
}


/// Writes the cursor when it differs from the last written one; returns the cursor now on disk.
pub fn save_if_changed(path: &Path, cursor: Cursor, saved: Cursor) -> Result<Cursor, SourceError> {
    if cursor == saved {
        Ok(saved)
    } else {
        write_cursor(path, cursor)?;
        Ok(cursor)
    }
}


fn log_report(report: &Report, pending: u64, limit: u64) {
    let Report {
        malformed,
        unknown,
        oversized,
        ..
    } = *report;
    if malformed + unknown + oversized > 0 {
        tracing::warn!(malformed, unknown, oversized, "export lines skipped");
    }
    if report.stop == Stop::Full {
        tracing::warn!(pending, limit, "spool full, reading paused");
    }
    if report.truncated {
        tracing::warn!("export file truncated or rewritten, read again from the start");
    }
}


/// One poll: drains the open file, persists the cursor, then follows a rotation (the old file is drained first).
pub fn poll(follower: &mut Follower, paths: &Paths, settings: &SourceSettings, line_limit: usize) -> Result<Report, SourceError> {
    let Follower { cursor, current } = follower;
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
            let drained = drain(file, cursor, paths, settings, line_limit)?;
            let saved = save_if_changed(&paths.cursor_file, *cursor, before)?;
            let follow = matches!(drained.stop, Stop::Eof | Stop::Partial);
            let next = if follow { rotated_file(&paths.export, cursor)? } else { None };
            save_if_changed(&paths.cursor_file, *cursor, saved)?;
            let lost = u64::from(next.is_some() && drained.stop == Stop::Partial);
            (
                Report {
                    rotated: next.is_some(),
                    malformed: drained.malformed + lost,
                    ..drained
                },
                next,
            )
        }
    };
    if let Some(next) = replacement {
        *current = Some(next);
    }
    log_report(&report, file_len(&paths.spool)?, settings.max_spool_bytes);
    Ok(report)
}
