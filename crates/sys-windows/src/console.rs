use crate::types::{CloseState, ConsoleError, ConsoleSize};


pub const MAX_CONSOLE_COLUMNS: u16 = 500;


pub const MAX_CONSOLE_ROWS: u16 = 200;


pub const SHELL_PROGRAM_NAME: &str = "cmd.exe";


pub const SHELL_ARGUMENTS: [&str; 1] = ["/D"];


pub const SHELL_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";


const PAIR: usize = 2;


pub const MAX_SESSION_LABEL_BYTES: usize = 64;


fn has_nul(text: &str) -> bool {
    text.contains('\0')
}


fn bad_directory(directory: &str) -> ConsoleError {
    ConsoleError::BadDirectory(directory.chars().take(MAX_SESSION_LABEL_BYTES).collect())
}


fn drive_of(directory: &str) -> Result<String, ConsoleError> {
    let mut characters = directory.chars();
    let letter = characters.next().filter(char::is_ascii_alphabetic);
    let colon = characters.next().filter(|character| *character == ':');
    let separator = characters.next().filter(|character| *character == '\\');
    let forbidden = directory.contains(['"', ';']) || has_nul(directory);
    match (letter, colon, separator, forbidden) {
        (Some(drive_letter), Some(drive_colon), Some(_), false) => Ok(format!("{drive_letter}{drive_colon}")),
        _ => Err(bad_directory(directory)),
    }
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
