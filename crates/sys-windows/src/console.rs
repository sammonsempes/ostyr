use crate::types::{CloseState, ConsoleError, ConsoleSize};
use crate::walk::split_volume_path;


pub const MAX_CONSOLE_COLUMNS: u16 = 500;


pub const MAX_CONSOLE_ROWS: u16 = 200;


pub const SHELL_PROGRAM_NAME: &str = "cmd.exe";


pub const SHELL_ARGUMENTS: [&str; 1] = ["/D"];


pub const SHELL_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";


const PAIR: usize = 2;


pub const MAX_SESSION_LABEL_BYTES: usize = 64;


pub const OUTPUT_CHUNK_BYTES: usize = 16_384;


pub const INPUT_CHUNK_BYTES: usize = 4_096;


pub const PIPE_BUFFER_BYTES: u32 = 65_536;


pub const DIRECTORY_UNITS: usize = 260;


fn has_nul(text: &str) -> bool {
    text.contains('\0')
}


pub const MAX_DIRECTORY_CHARS: usize = 240;


pub const MAX_ERROR_DIRECTORY_CHARS: usize = 64;


pub const CUT_MARKER: &str = "...[cut]";


/// The text of a refused path or directory for an error: cut at `MAX_ERROR_DIRECTORY_CHARS` with `CUT_MARKER`.
pub fn shown_text(text: &str) -> String {
    let cut = text.chars().count() > MAX_ERROR_DIRECTORY_CHARS;
    let shown = text.chars().take(MAX_ERROR_DIRECTORY_CHARS).collect::<String>();
    if cut {
        format!("{shown}{CUT_MARKER}")
    } else {
        shown
    }
}


fn bad_directory(directory: &str) -> ConsoleError {
    ConsoleError::BadDirectory(shown_text(directory))
}


/// The volume root (`C:`) of an absolute local path without quote, `;`, slash or NUL, or `None`.
pub fn drive_root(path: &str) -> Option<String> {
    let forbidden = path.contains(['"', ';', '/']) || path.chars().count() > MAX_DIRECTORY_CHARS;
    split_volume_path(path)
        .ok()
        .filter(|_| !forbidden)
        .map(|volume| volume.root.trim_end_matches('\\').to_string())
}


fn drive_of(directory: &str) -> Result<String, ConsoleError> {
    drive_root(directory).ok_or_else(|| bad_directory(directory))
}


/// The cmd.exe command line: the quoted `cmd.exe` of the system directory followed by the fixed arguments (`/D` blocks AutoRun).
pub fn command_line(system_directory: &str) -> Result<String, ConsoleError> {
    drive_of(system_directory)?;
    let line = std::iter::once(format!("\"{system_directory}\\{SHELL_PROGRAM_NAME}\""))
        .chain(SHELL_ARGUMENTS.iter().map(|argument| (*argument).to_string()))
        .collect::<Vec<_>>();
    Ok(line.join(" "))
}


/// A console size in `1..=MAX_CONSOLE_COLUMNS` by `1..=MAX_CONSOLE_ROWS`.
pub fn console_size(columns: u32, rows: u32) -> Result<ConsoleSize, ConsoleError> {
    let checked_columns = u16::try_from(columns).ok().filter(|value| (1..=MAX_CONSOLE_COLUMNS).contains(value));
    let checked_rows = u16::try_from(rows).ok().filter(|value| (1..=MAX_CONSOLE_ROWS).contains(value));
    let size = checked_columns.zip(checked_rows).map(|(columns_value, rows_value)| ConsoleSize {
        columns: columns_value,
        rows: rows_value,
    });
    size.ok_or(ConsoleError::BadSize {
        columns,
        rows,
        max_columns: MAX_CONSOLE_COLUMNS,
        max_rows: MAX_CONSOLE_ROWS,
    })
}


/// The fixed environment of the shell from the system and windows directories and the session label.
pub fn session_environment(system_directory: &str, windows_directory: &str, session: &str) -> Result<Vec<u16>, ConsoleError> {
    let system_drive_text = drive_of(windows_directory)?;
    drive_of(system_directory)?;
    check_session_label(session)?;
    let temp = format!("{windows_directory}\\Temp");
    let program = format!("{system_directory}\\{SHELL_PROGRAM_NAME}");
    let path = format!("{system_directory};{windows_directory};{system_directory}\\Wbem");
    let entries = [
        ("SystemRoot", windows_directory),
        ("windir", windows_directory),
        ("SystemDrive", system_drive_text.as_str()),
        ("ComSpec", program.as_str()),
        ("PATH", path.as_str()),
        ("PATHEXT", SHELL_PATHEXT),
        ("TEMP", temp.as_str()),
        ("TMP", temp.as_str()),
        ("OSTYR_SESSION", session),
    ];
    environment_block(&entries)
}


/// A session label: `[A-Za-z0-9._-]`, 1 to `MAX_SESSION_LABEL_BYTES` bytes, no leading `-`.
pub fn check_session_label(session: &str) -> Result<(), ConsoleError> {
    let grammar = session
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    let refused = session.is_empty() || session.len() > MAX_SESSION_LABEL_BYTES || session.starts_with('-') || !grammar;
    if refused {
        Err(ConsoleError::BadSessionLabel {
            max_bytes: MAX_SESSION_LABEL_BYTES,
        })
    } else {
        Ok(())
    }
}


/// A UTF-16 environment block: `NAME=value` entries (names `[A-Za-z0-9_]`) sorted by ASCII-folded name, each NUL terminated, then a final NUL.
pub fn environment_block(entries: &[(&str, &str)]) -> Result<Vec<u16>, ConsoleError> {
    let mut keyed = entries
        .iter()
        .map(|(name, value)| checked_entry(name, value))
        .collect::<Result<Vec<(String, String)>, ConsoleError>>()?;
    keyed.sort();
    let duplicate = keyed.windows(PAIR).find_map(|pair| match pair {
        [first, second] if first.0 == second.0 => Some(first.0.clone()),
        _ => None,
    });
    let block = keyed
        .iter()
        .flat_map(|(_, line)| line.encode_utf16().chain(std::iter::once(0)))
        .chain(std::iter::once(0))
        .chain(keyed.is_empty().then_some(0))
        .collect::<Vec<u16>>();
    match duplicate {
        Some(name) => Err(ConsoleError::DuplicateEnvironmentName { name }),
        None => Ok(block),
    }
}


fn checked_entry(name: &str, value: &str) -> Result<(String, String), ConsoleError> {
    let name_refused = name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_');
    if name_refused {
        Err(ConsoleError::BadEnvironmentName)
    } else if has_nul(value) {
        Err(ConsoleError::BadEnvironmentValue { name: name.to_string() })
    } else {
        Ok((name.to_ascii_uppercase(), format!("{name}={value}")))
    }
}


/// Moves an open console to closed, refusing a second explicit close.
pub fn begin_close(state: &mut CloseState) -> Result<(), ConsoleError> {
    let verdict = match state {
        CloseState::Open => Ok(()),
        CloseState::Closed => Err(ConsoleError::AlreadyClosed),
    };
    *state = CloseState::Closed;
    verdict
}


/// Whether `Drop` still has to close: true once, false after any close.
pub fn close_on_drop(state: &mut CloseState) -> bool {
    let pending = *state == CloseState::Open;
    *state = CloseState::Closed;
    pending
}


/// Refuses an input write larger than `INPUT_CHUNK_BYTES`.
pub fn check_input_len(bytes: usize) -> Result<(), ConsoleError> {
    if bytes > INPUT_CHUNK_BYTES {
        Err(ConsoleError::InputTooLarge {
            bytes,
            max_bytes: INPUT_CHUNK_BYTES,
        })
    } else {
        Ok(())
    }
}


/// The text of a directory a `Get...DirectoryW` call wrote: its length must be non-zero and below the buffer size.
pub fn directory_text(operation: &'static str, buffer: &[u16], length: u32) -> Result<String, ConsoleError> {
    let count = usize::try_from(length).ok().filter(|wanted| *wanted > 0 && *wanted < buffer.len());
    let units = count.and_then(|wanted| buffer.get(..wanted));
    units
        .and_then(|text| String::from_utf16(text).ok())
        .ok_or(ConsoleError::DirectoryRead { operation })
}


/// UTF-16 text with the terminating NUL a Windows call expects.
pub fn wide_null(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(std::iter::once(0)).collect()
}


/// The `COORD` values (columns, rows) of a checked size.
pub fn coordinates(size: ConsoleSize) -> (i16, i16) {
    (
        i16::try_from(size.columns).unwrap_or(i16::MAX),
        i16::try_from(size.rows).unwrap_or(i16::MAX),
    )
}
