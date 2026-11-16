use thiserror::Error;


#[derive(Debug, Error)]
pub enum PathError {
    #[error("the path is {bytes} bytes, more than {max}")]
    TooLong { bytes: usize, max: usize },
    #[error("the path is not absolute")]
    NotAbsolute,
    #[error("the path holds a character outside letters, digits and ._/-+@")]
    Character,
    #[error("the path is the root directory")]
    Root,
    #[error("the path holds an empty, `.` or `..` component")]
    Component,
    #[error("a path component is longer than the {max} bytes a Tetragon Postfix value takes")]
    NameTooLong { max: usize },
    #[error("a prefix path must end with a slash and a file path must not")]
    Kind,
}


#[derive(Debug, Error)]
pub enum RoleError {
    #[error("the role name is not 1 to {max} lowercase letters, digits or inner hyphens starting with a letter")]
    Name { max: usize },
    #[error("{count} watched paths, more than {max}")]
    TooManyWatched { count: usize, max: usize },
    #[error("{count} honeytokens, more than {max}")]
    TooManyHoneytokens { count: usize, max: usize },
    #[error("watched path {index} is refused: {source}")]
    Watched {
        index: usize,
        #[source]
        source: PathError,
    },
    #[error("honeytoken {index} is refused: {source}")]
    Honeytoken {
        index: usize,
        #[source]
        source: PathError,
    },
    #[error("watched path {index} repeats watched path {first}")]
    DuplicateWatched { index: usize, first: usize },
    #[error("honeytoken {index} repeats honeytoken {first}")]
    DuplicateHoneytoken { index: usize, first: usize },
}


#[derive(Debug, Error)]
pub enum TableError {
    #[error("the table is {bytes} bytes, more than {max}")]
    TooLarge { bytes: usize, max: usize },
    #[error("the table is not valid: {0}")]
    Parse(#[source] Box<serde_saphyr::Error>),
    #[error("table version {found} is not supported")]
    Version { found: u32 },
    #[error("{count} roles, more than {max}")]
    TooManyRoles { count: usize, max: usize },
    #[error("role {index} is refused: {source}")]
    Role {
        index: usize,
        #[source]
        source: RoleError,
    },
    #[error("role {index} repeats the name of role {first}")]
    DuplicateRole { index: usize, first: usize },
}


#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("the role watches nothing and holds no honeytoken")]
    Empty,
    #[error("{count} watched files, more than the {max} one Tetragon selector takes")]
    TooManyFiles { count: usize, max: usize },
    #[error("{count} watched prefixes, more than the {max} one Tetragon selector takes")]
    TooManyPrefixes { count: usize, max: usize },
    #[error("{count} honeytokens, more than the {max} one Tetragon selector takes")]
    TooManyHoneytokens { count: usize, max: usize },
    #[error("{call} would need {count} selectors, more than the {max} one Tetragon kprobe takes")]
    TooManySelectors { call: String, count: usize, max: usize },
    #[error("policy {policy} would need {count} `{operator}` selectors, more than the {max} one Tetragon policy loads")]
    TooManyMaps {
        policy: String,
        operator: String,
        count: usize,
        max: usize,
    },
    #[error("the policy could not be serialised: {0}")]
    Serialize(#[from] serde_saphyr::SerializeError),
}


#[derive(Debug, Error)]
pub enum CliError {
    #[error("the table could not be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("the table is refused: {0}")]
    Table(#[from] TableError),
    #[error("no role named {0}")]
    NoRole(String),
    #[error("the role is refused: {0}")]
    Policy(#[from] PolicyError),
}
