use crate::model::MAX_PATH_LENGTH;


pub const UNIX_ROOT: &str = "/";


pub const DRIVE_ONLY_LENGTH: usize = 2;


pub const UNC_LENGTH: usize = 2;


pub const PARENT: &str = "..";


pub fn is_separator(character: char) -> bool {
    matches!(character, '/' | '\\')
}


fn is_drive(part: &str) -> bool {
    let mut characters = part.chars();
    matches!((characters.next(), characters.next(), characters.next()), (Some(letter), Some(':'), None) if letter.is_ascii_alphabetic())
}


/// Components of a plain absolute path (`/x` or `C:\x`), or `None` when relative, too long, holding a control character, a `..`, a UNC start or a component ending in a dot or space.
pub fn absolute_components(path: &str) -> Option<Vec<&str>> {
    let parts: Vec<&str> = path.split(is_separator).filter(|part| !part.is_empty()).collect();
    let rooted = path.starts_with('/');
    let drive_rooted = !rooted && path.len() > DRIVE_ONLY_LENGTH && parts.first().is_some_and(|first| is_drive(first));
    let unc = path.chars().take(UNC_LENGTH).filter(|character| is_separator(*character)).count() == UNC_LENGTH;
    let normalised = parts.iter().all(|part| !part.ends_with(['.', ' ']));
    let plain = path.len() <= MAX_PATH_LENGTH && !path.chars().any(char::is_control) && !parts.contains(&PARENT) && !unc && normalised;
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
