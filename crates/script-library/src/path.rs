use crate::model::MAX_PATH_LENGTH;


pub const UNIX_ROOT: &str = "/";


pub const DRIVE_ONLY_LENGTH: usize = 2;


pub const UNC_LENGTH: usize = 2;


pub const PARENT: &str = "..";


pub const RESERVED_NAMES: &[&str] = &[
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "COM\u{b9}",
    "COM\u{b2}",
    "COM\u{b3}",
    "LPT\u{b9}",
    "LPT\u{b2}",
    "LPT\u{b3}",
    "CONIN$",
    "CONOUT$",
    "CLOCK$",
];


pub fn is_separator(character: char) -> bool {
    matches!(character, '/' | '\\')
}


/// A Windows device name in any case, whatever follows it: an extension, a stream (`NUL:`), trailing spaces (`nul .txt`).
pub fn is_reserved_name(part: &str) -> bool {
    part.split(['.', ':'])
        .next()
        .map(|stem| stem.trim_end_matches(' '))
        .is_some_and(|stem| RESERVED_NAMES.iter().any(|name| name.eq_ignore_ascii_case(stem)))
}


fn is_drive(part: &str) -> bool {
    let mut characters = part.chars();
    matches!((characters.next(), characters.next(), characters.next()), (Some(letter), Some(':'), None) if letter.is_ascii_alphabetic())
}


/// Components of a plain absolute path (`/x` or `C:\x`); `None` when relative, too long, control character, `..`, UNC, device name or dot/space end.
pub fn absolute_components(path: &str) -> Option<Vec<&str>> {
    let parts: Vec<&str> = path.split(is_separator).filter(|part| !part.is_empty()).collect();
    let rooted = path.starts_with('/');
    let drive_rooted = !rooted && path.len() > DRIVE_ONLY_LENGTH && parts.first().is_some_and(|first| is_drive(first));
    let unc = path.chars().take(UNC_LENGTH).filter(|character| is_separator(*character)).count() == UNC_LENGTH;
    let normalised = parts.iter().all(|part| !part.ends_with(['.', ' ']));
    let device_free = parts.iter().all(|part| !is_reserved_name(part));
    let plain = path.len() <= MAX_PATH_LENGTH && !path.chars().any(char::is_control) && !parts.contains(&PARENT) && !unc && normalised && device_free;
    let root: Vec<&str> = if rooted { vec![UNIX_ROOT] } else { Vec::new() };
    (plain && (rooted || drive_rooted)).then(|| root.into_iter().chain(parts).collect())
}


/// True when `path` is a plain absolute path equal to or below one of the prefixes, compared by component.
pub fn is_under_prefixes(path: &str, prefixes: &[String]) -> bool {
    absolute_components(path).is_some_and(|components| {
        prefixes
            .iter()
            .filter_map(|prefix| absolute_components(prefix))
            .any(|allowed| components.starts_with(&allowed))
    })
}
