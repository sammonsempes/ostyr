use crate::model::PathForm;


pub const NT_PREFIXES: [&str; 5] = [r"\\?\", r"\\.\", r"\??\", r"\device\", "/??/"];


pub const PATH_LIKE_CHARACTERS: [char; 8] = ['/', '\\', ':', '~', '%', '$', '*', '?'];


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavour {
    Windows,
    Posix,
}


/// `components` are lowercased and drive-less for the deny lists (`C:\Users` also covers `D:\Users`); `drive` and `exact` serve exact binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalPath {
    pub flavour: Flavour,
    pub drive: Option<char>,
    pub components: Vec<String>,
    pub exact: Vec<String>,
}


pub fn windows_root(value: &str) -> Result<(Flavour, &str), PathForm> {
    let mut chars = value.chars();
    let drive = chars.next().filter(char::is_ascii_alphabetic);
    let colon = chars.next().filter(|candidate| *candidate == ':');
    match (drive, colon, chars.next()) {
        (Some(_), Some(_), Some('\\')) => Ok((Flavour::Windows, chars.as_str())),
        (Some(_), Some(_), Some('/')) => Err(PathForm::MixedSeparators),
        (Some(_), Some(_), _) => Err(PathForm::DriveRelative),
        _ => Err(PathForm::NotAbsolute),
    }
}


/// Prefix forms are tested first, because their `?` and `.` would otherwise read as a wildcard or a dot.
pub fn split_root(value: &str) -> Result<(Flavour, &str), PathForm> {
    let lower = value.to_ascii_lowercase();
    if NT_PREFIXES.iter().any(|prefix| lower.starts_with(prefix)) {
        Err(PathForm::NtDevice)
    } else if value.starts_with(r"\\") {
        Err(PathForm::Unc)
    } else if value.starts_with('~') {
        Err(PathForm::Tilde)
    } else if let Some(rest) = value.strip_prefix('/') {
        Ok((Flavour::Posix, rest))
    } else {
        windows_root(value)
    }
}


pub fn character_form(character: char) -> Option<PathForm> {
    match character {
        '*' | '?' => Some(PathForm::Wildcard),
        '%' | '$' => Some(PathForm::EnvironmentVariable),
        '<' | '>' | '"' | '|' => Some(PathForm::ReservedCharacter),
        other if other.is_control() => Some(PathForm::ControlCharacter),
        _ => None,
    }
}


pub fn has_short_name(component: &str) -> bool {
    component
        .split('~')
        .skip(1)
        .any(|after| after.starts_with(|digit: char| digit.is_ascii_digit()))
}


pub fn component_form(component: &str, is_last: bool) -> Option<PathForm> {
    if component.is_empty() {
        Some(if is_last {
            PathForm::TrailingSeparator
        } else {
            PathForm::DoubledSeparator
        })
    } else if component == "." || component == ".." {
        Some(PathForm::DotSegment)
    } else if component.ends_with('.') || component.ends_with(' ') {
        Some(PathForm::TrailingDotOrSpace)
    } else if component.starts_with('~') {
        Some(PathForm::Tilde)
    } else if has_short_name(component) {
        Some(PathForm::ShortName)
    } else {
        None
    }
}


pub fn separator_checks(flavour: Flavour, rest: &str) -> Option<PathForm> {
    let foreign = match flavour {
        Flavour::Windows => '/',
        Flavour::Posix => '\\',
    };
    if !rest.is_ascii() {
        Some(PathForm::NonAscii)
    } else if rest.contains(':') {
        Some(PathForm::AlternateStream)
    } else if rest.contains(foreign) {
        Some(PathForm::MixedSeparators)
    } else {
        rest.chars().find_map(character_form)
    }
}


pub fn split_components(flavour: Flavour, rest: &str) -> Result<Vec<String>, PathForm> {
    let separator = match flavour {
        Flavour::Windows => '\\',
        Flavour::Posix => '/',
    };
    let parts: Vec<&str> = rest.split(separator).collect();
    let last = parts.len().saturating_sub(1);
    if rest.is_empty() {
        Ok(Vec::new())
    } else {
        parts
            .iter()
            .enumerate()
            .try_for_each(|(index, part)| component_form(part, index == last).map_or(Ok(()), Err))?;
        Ok(parts.iter().map(|part| part.to_lowercase()).collect())
    }
}


pub fn split_exact(flavour: Flavour, rest: &str) -> Vec<String> {
    let separator = match flavour {
        Flavour::Windows => '\\',
        Flavour::Posix => '/',
    };
    if rest.is_empty() {
        Vec::new()
    } else {
        rest.split(separator).map(str::to_owned).collect()
    }
}


/// A path is either already canonical or refused: nothing is ever rewritten.
pub fn canonical_path(value: &str) -> Result<CanonicalPath, PathForm> {
    let (flavour, rest) = split_root(value)?;
    separator_checks(flavour, rest).map_or(Ok(()), Err)?;
    let components = split_components(flavour, rest)?;
    let drive = value
        .chars()
        .next()
        .filter(|_| flavour == Flavour::Windows)
        .map(|letter| letter.to_ascii_lowercase());
    let exact = split_exact(flavour, rest);
    Ok(CanonicalPath {
        flavour,
        drive,
        components,
        exact,
    })
}


pub fn command_character_form(character: char) -> Option<PathForm> {
    match character {
        '"' | '\'' | '`' | '^' => Some(PathForm::Quoting),
        ' ' => None,
        other if other.is_control() || other.is_whitespace() => Some(PathForm::ControlCharacter),
        _ => None,
    }
}


pub fn is_path_like(token: &str) -> bool {
    token.contains(PATH_LIKE_CHARACTERS)
}


/// Executable forms: `"C:\Program Files\x.exe" args`, else the first space-separated token.
pub fn split_executable(value: &str) -> Result<(&str, &str), PathForm> {
    if let Some(quoted) = value.strip_prefix('"') {
        let (executable, rest) = quoted.split_once('"').ok_or(PathForm::Quoting)?;
        if rest.is_empty() || rest.starts_with(' ') {
            Ok((executable, rest))
        } else {
            Err(PathForm::Quoting)
        }
    } else {
        Ok(value.split_once(' ').unwrap_or((value, "")))
    }
}


/// The executable and every path-like token; `-o/tmp/x` and `--out=/tmp/x` are not absolute, so they are refused.
pub fn command_line_paths(value: &str) -> Result<Vec<CanonicalPath>, PathForm> {
    let (executable, rest) = split_executable(value.trim_start_matches(' '))?;
    executable
        .chars()
        .chain(rest.chars())
        .find_map(command_character_form)
        .map_or(Ok(()), Err)?;
    if executable.is_empty() {
        Err(PathForm::Empty)
    } else {
        std::iter::once(executable)
            .chain(rest.split(' ').filter(|token| is_path_like(token)))
            .map(canonical_path)
            .collect()
    }
}


/// Equal, or one is an ancestor of the other: excluding a parent covers the child.
pub fn covers(left: &CanonicalPath, right: &CanonicalPath) -> bool {
    left.flavour == right.flavour && (left.components.starts_with(&right.components) || right.components.starts_with(&left.components))
}
