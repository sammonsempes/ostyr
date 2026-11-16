use crate::error::{PathError, RoleError, TableError};
use crate::limits::{MAX_NAME_BYTES, MAX_ROLE_NAME_BYTES, SUPPORTED_VERSION};
use crate::model::{Limits, Role, RoleTable, WatchKind};


const ALLOWED_PUNCTUATION: &[u8] = b"._/-+@";


/// Loads a role table strictly: size capped before parsing, unknown keys refused, every path and name checked, every refusal naming its index.
pub fn load_roles(text: &str, limits: &Limits) -> Result<RoleTable, TableError> {
    check_size(text, limits)?;
    let options = serde_saphyr::options! { with_snippet: false };
    let table: RoleTable = serde_saphyr::from_str_with_options(text, options).map_err(|source| TableError::Parse(Box::new(source)))?;
    check_table(&table, limits)?;
    Ok(table)
}


/// Refuses a table larger than the cap, before the parser sees it.
pub fn check_size(text: &str, limits: &Limits) -> Result<(), TableError> {
    let bytes = text.len();
    if bytes > limits.max_table_bytes {
        Err(TableError::TooLarge {
            bytes,
            max: limits.max_table_bytes,
        })
    } else {
        Ok(())
    }
}


/// Checks the version, the role count, every role and the uniqueness of role names.
pub fn check_table(table: &RoleTable, limits: &Limits) -> Result<(), TableError> {
    if table.version != SUPPORTED_VERSION {
        Err(TableError::Version { found: table.version })
    } else if table.roles.len() > limits.max_roles {
        Err(TableError::TooManyRoles {
            count: table.roles.len(),
            max: limits.max_roles,
        })
    } else {
        table
            .roles
            .iter()
            .enumerate()
            .try_for_each(|(index, role)| check_role(role, limits).map_err(|source| TableError::Role { index, source }))?;
        let names: Vec<&str> = table.roles.iter().map(|role| role.name.as_str()).collect();
        match first_duplicate(&names) {
            Some((index, first)) => Err(TableError::DuplicateRole { index, first }),
            None => Ok(()),
        }
    }
}


/// Checks the name, the counts, every path and the uniqueness of paths of one role.
pub fn check_role(role: &Role, limits: &Limits) -> Result<(), RoleError> {
    check_name(&role.name)?;
    if role.watched.len() > limits.max_watched {
        Err(RoleError::TooManyWatched {
            count: role.watched.len(),
            max: limits.max_watched,
        })
    } else if role.honeytokens.len() > limits.max_honeytokens {
        Err(RoleError::TooManyHoneytokens {
            count: role.honeytokens.len(),
            max: limits.max_honeytokens,
        })
    } else {
        role.watched.iter().enumerate().try_for_each(|(index, watched)| {
            check_path(&watched.path, watched.kind, limits.max_path_bytes).map_err(|source| RoleError::Watched { index, source })
        })?;
        role.honeytokens.iter().enumerate().try_for_each(|(index, token)| {
            check_path(&token.path, WatchKind::File, limits.max_path_bytes).map_err(|source| RoleError::Honeytoken { index, source })
        })?;
        let watched: Vec<&str> = role.watched.iter().map(|item| item.path.as_str()).collect();
        let tokens: Vec<&str> = role.honeytokens.iter().map(|item| item.path.as_str()).collect();
        match (first_duplicate(&watched), first_duplicate(&tokens)) {
            (Some((index, first)), _) => Err(RoleError::DuplicateWatched { index, first }),
            (None, Some((index, first))) => Err(RoleError::DuplicateHoneytoken { index, first }),
            (None, None) => Ok(()),
        }
    }
}


/// A role name is lowercase letters, digits and inner hyphens, starting with a letter: it becomes part of a Kubernetes-style policy name.
pub fn check_name(name: &str) -> Result<(), RoleError> {
    let shape_ok = name.starts_with(|first: char| first.is_ascii_lowercase()) && !name.ends_with('-');
    let characters_ok = name
        .chars()
        .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-');
    if shape_ok && characters_ok && name.len() <= MAX_ROLE_NAME_BYTES {
        Ok(())
    } else {
        Err(RoleError::Name { max: MAX_ROLE_NAME_BYTES })
    }
}


/// Checks one absolute path: ASCII allowlist, no empty, `.` or `..` component, a trailing slash exactly for a prefix.
pub fn check_path(path: &str, kind: WatchKind, max_bytes: usize) -> Result<(), PathError> {
    let ends_with_slash = path.ends_with('/');
    let body = path.strip_suffix('/').unwrap_or(path);
    if path.len() > max_bytes {
        Err(PathError::TooLong {
            bytes: path.len(),
            max: max_bytes,
        })
    } else if !path.starts_with('/') {
        Err(PathError::NotAbsolute)
    } else if !path
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || ALLOWED_PUNCTUATION.contains(&byte))
    {
        Err(PathError::Character)
    } else if path == "/" {
        Err(PathError::Root)
    } else if body.split('/').skip(1).any(|part| part.is_empty() || part == "." || part == "..") {
        Err(PathError::Component)
    } else if body.split('/').any(|part| part.len() > MAX_NAME_BYTES) {
        Err(PathError::NameTooLong { max: MAX_NAME_BYTES })
    } else if ends_with_slash != (kind == WatchKind::Prefix) {
        Err(PathError::Kind)
    } else {
        Ok(())
    }
}


/// The index of the first item equal to an earlier one and the index of that earlier one.
pub fn first_duplicate(items: &[&str]) -> Option<(usize, usize)> {
    items.iter().enumerate().find_map(|(index, current)| {
        items
            .iter()
            .take(index)
            .position(|earlier| earlier == current)
            .map(|first| (index, first))
    })
}
