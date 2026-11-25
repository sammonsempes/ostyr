use crate::types::{CloseState, ConsoleError, ConsoleSize};


pub const MAX_CONSOLE_COLUMNS: u16 = 500;


pub const MAX_CONSOLE_ROWS: u16 = 200;


pub const SHELL_PROGRAM_NAME: &str = "cmd.exe";


pub const SHELL_ARGUMENTS: [&str; 1] = ["/D"];


pub const SHELL_PATHEXT: &str = ".COM;.EXE;.BAT;.CMD";


const PAIR: usize = 2;


fn has_nul(text: &str) -> bool {
    text.contains('\0')
}


/// The cmd.exe command line: the quoted program path followed by the fixed arguments (`/D` blocks AutoRun).
pub fn command_line(program: &str) -> Result<String, ConsoleError> {
    let refused = program.is_empty() || program.contains('"') || has_nul(program);
    let line = std::iter::once(format!("\"{program}\""))
        .chain(SHELL_ARGUMENTS.iter().map(|argument| (*argument).to_string()))
        .collect::<Vec<_>>();
    if refused {
        Err(ConsoleError::BadProgramPath)
    } else {
        Ok(line.join(" "))
    }
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
    let mut characters = windows_directory.chars();
    let drive = characters
        .next()
        .filter(char::is_ascii_alphabetic)
        .zip(characters.next().filter(|colon| *colon == ':'));
    let system_drive = drive.map(|(letter, colon)| format!("{letter}{colon}"));
    let system_drive_text = system_drive.ok_or_else(|| ConsoleError::BadWindowsDirectory(windows_directory.to_string()))?;
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


/// A UTF-16 environment block: `NAME=value` entries sorted case-insensitively by name, each NUL terminated, then a final NUL.
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
    let name_refused = name.is_empty() || name.contains('=') || has_nul(name);
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
