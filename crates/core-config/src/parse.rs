use crate::error::ConfigError;
#[cfg(unix)]
use rustix::fs::{open, Mode, OFlags};
use serde::de::{DeserializeOwned, Error as _};
use serde_path_to_error::{Path as FieldPath, Segment};
use serde_saphyr::{Error as YamlError, ExternalMessageSource, Location};
#[cfg(unix)]
use std::fs::OpenOptions;
use std::fs::{File, Metadata};
use std::io::Read;
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;


pub const ROOT_FIELD_PATH: &str = ".";


pub const MAX_FILE_BYTES: u64 = 8_388_608;


/// Reads at most `max` bytes; one byte more is refused with `ConfigError::TooLarge` naming the file.
pub fn read_text_capped(reader: &mut dyn Read, file: &str, max: u64) -> Result<String, ConfigError> {
    let mut bytes = Vec::new();
    Read::take(reader, max.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| ConfigError::Io {
            file: file.to_string(),
            source,
        })?;
    if bytes.len() as u64 > max {
        Err(ConfigError::TooLarge { file: file.to_string(), max })
    } else {
        String::from_utf8(bytes).map_err(|source| ConfigError::Io {
            file: file.to_string(),
            source: std::io::Error::new(std::io::ErrorKind::InvalidData, source),
        })
    }
}


pub fn read_text(reader: &mut dyn Read, file: &str) -> Result<String, ConfigError> {
    read_text_capped(reader, file, MAX_FILE_BYTES)
}


pub const NOT_REGULAR_REASON: &str = "not a regular file";


fn io_at(file: &str) -> impl FnOnce(std::io::Error) -> ConfigError + '_ {
    move |source| ConfigError::Io {
        file: file.to_string(),
        source,
    }
}


fn refuse_unless_regular(metadata: &Metadata, file: &str) -> Result<(), ConfigError> {
    metadata.is_file().then_some(()).ok_or_else(|| ConfigError::WatchedFile {
        file: file.to_string(),
        reason: NOT_REGULAR_REASON.to_string(),
    })
}


/// `O_PATH` follows symlinks and runs no driver, the handle is judged by `fstat`, then reopened non-blocking through `/proc/self/fd`.
#[cfg(unix)]
pub fn open_regular(path: &Path, file: &str) -> Result<File, ConfigError> {
    open_regular_through(path, file, reopen_non_blocking)
}


/// The reopen step of `open_regular`, injectable so a test sees that a refused anchor never reaches it.
#[cfg(unix)]
pub fn open_regular_through(path: &Path, file: &str, reopen: fn(&Path) -> std::io::Result<File>) -> Result<File, ConfigError> {
    let anchor = File::from(
        open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
            .map_err(std::io::Error::from)
            .map_err(io_at(file))?,
    );
    refuse_unless_regular(&anchor.metadata().map_err(io_at(file))?, file)?;
    let handle = reopen(Path::new(&format!("/proc/self/fd/{}", anchor.as_raw_fd()))).map_err(io_at(file))?;
    refuse_unless_regular(&handle.metadata().map_err(io_at(file))?, file)?;
    Ok(handle)
}


/// Plain `open` of `O_PATH` is dropped by Rust's musl build, so the anchor goes through rustix's raw syscall; this reopen is an ordinary open.
#[cfg(unix)]
pub fn reopen_non_blocking(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NONBLOCK | libc::O_NOCTTY | libc::O_CLOEXEC);
    options.open(path)
}


#[cfg(not(unix))]
pub fn open_regular(path: &Path, file: &str) -> Result<File, ConfigError> {
    let handle = File::open(path).map_err(io_at(file))?;
    refuse_unless_regular(&handle.metadata().map_err(io_at(file))?, file)?;
    Ok(handle)
}


/// The bytes of a regular file, at most `max`; one more is `TooLarge`, a non-regular file is refused before any driver open.
pub fn read_bytes_capped(path: &Path, max: u64) -> Result<Vec<u8>, ConfigError> {
    let file = path.display().to_string();
    let handle = open_regular(path, &file)?;
    let mut bytes = Vec::new();
    handle.take(max.saturating_add(1)).read_to_end(&mut bytes).map_err(io_at(&file))?;
    if bytes.len() as u64 > max {
        Err(ConfigError::TooLarge { file, max })
    } else {
        Ok(bytes)
    }
}


/// Opens without blocking (a FIFO at the path cannot hang the reader) and refuses a non-regular file on the opened handle.
pub fn read_file(path: &Path) -> Result<String, ConfigError> {
    let file = path.display().to_string();
    let mut handle = open_regular(path, &file)?;
    read_text(&mut handle, &file)
}


/// Line and column of a parser location, `(0, 0)` when the parser gave none.
pub fn position_of(location: Option<Location>) -> (u64, u64) {
    location.map_or((0, 0), |known| (known.line(), known.column()))
}


/// Names a schema list such as the expected fields; the schema is code, not document content.
fn expected_list(expected: &[&str]) -> String {
    expected.iter().map(|name| format!("`{name}`")).collect::<Vec<_>>().join(", ")
}


/// The error behind any alias replay or snippet wrapper, which carry document text of their own.
pub fn root_cause(error: &YamlError) -> &YamlError {
    std::iter::successors(Some(error), |current| match current {
        YamlError::AliasError { error: inner, .. } | YamlError::WithSnippet { error: inner, .. } => Some(inner.as_ref()),
        _ => None,
    })
    .last()
    .unwrap_or(error)
}


/// The error class with every key, value, tag and name taken from the document removed; unlisted variants get a fixed class.
pub fn describe_error(error: &YamlError) -> String {
    match root_cause(error) {
        YamlError::SerdeUnknownField { expected, .. } => format!("unknown field, expected one of {}", expected_list(expected)),
        YamlError::SerdeUnknownVariant { expected, .. } => format!("unknown variant, expected one of {}", expected_list(expected)),
        YamlError::SerdeInvalidType { expected, .. } => format!("invalid type, expected {expected}"),
        YamlError::SerdeInvalidValue { expected, .. } => format!("invalid value, expected {expected}"),
        YamlError::DuplicateMappingKey { .. } => "duplicate mapping key".to_string(),
        YamlError::TaggedEnumMismatch { target, .. } => format!("tag does not match {target}"),
        YamlError::SerdeVariantId { .. } => "invalid variant identifier".to_string(),
        YamlError::NonFiniteFloat { .. } => "non-finite float".to_string(),
        YamlError::QuotingRequired { .. } => "value requires quotes".to_string(),
        YamlError::Message { msg, .. } => bounded_message(&strip_serde_names(msg)),
        YamlError::InvalidScalar { ty, .. } => format!("invalid {ty}"),
        YamlError::ExternalMessage { source, .. } if matches!(source.as_ref(), ExternalMessageSource::Parser(_)) => "YAML syntax error".to_string(),
        YamlError::ExternalMessage { .. } | YamlError::HookError { .. } => "validation hook error".to_string(),
        YamlError::CyclicInclude { .. } | YamlError::ResolverError { .. } | YamlError::UnsupportedIncludeForm { .. } => "include error".to_string(),
        YamlError::UnresolvedProperty { .. }
        | YamlError::InvalidPropertyName { .. }
        | YamlError::PropertyRequiredButUnset { .. }
        | YamlError::PropertyRequiredButEmpty { .. } => "property error".to_string(),
        YamlError::UnsupportedTag { .. } => "unsupported tag".to_string(),
        known @ (YamlError::Eof { .. }
        | YamlError::MultipleDocuments { .. }
        | YamlError::Unexpected { .. }
        | YamlError::UnexpectedSequenceEnd { .. }
        | YamlError::UnexpectedMappingEnd { .. }
        | YamlError::SerdeMissingField { .. }
        | YamlError::SerdeInvalidLength { .. }
        | YamlError::UnknownAnchor { .. }) => known.to_string(),
        _ => "invalid document".to_string(),
    }
}


/// Maximum bytes of a mapping key shown in a field path.
pub const MAX_KEY_BYTES: usize = 64;


/// Maximum characters of a validation message kept in an error.
pub const MAX_MESSAGE_CHARS: usize = 256;


/// A key shaped like a schema identifier (`[a-z][a-z0-9_]*`) is shown, any other text from the document is `<key>`.
pub fn shown_key(key: &str) -> String {
    let mut chars = key.chars();
    let identifier = key.len() <= MAX_KEY_BYTES
        && chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && chars.all(|next| next.is_ascii_lowercase() || next.is_ascii_digit() || next == '_');
    if identifier {
        key.to_string()
    } else {
        "<key>".to_string()
    }
}


/// Serde prefixes whose message embeds a name taken from the document, as in a flattened struct.
const NAMING_PREFIXES: [&str; 3] = ["unknown field `", "unknown variant `", "duplicate field `"];


/// Cuts the document name out of a message serde built itself; other messages pass unchanged.
pub fn strip_serde_names(message: &str) -> String {
    NAMING_PREFIXES
        .iter()
        .find(|prefix| message.starts_with(**prefix))
        .map_or_else(|| message.to_string(), |prefix| prefix.trim_end_matches(" `").to_string())
}


/// A validation message bounded to `MAX_MESSAGE_CHARS` characters with control characters escaped.
pub fn bounded_message(message: &str) -> String {
    message
        .chars()
        .take(MAX_MESSAGE_CHARS)
        .flat_map(|character| character.escape_default().collect::<Vec<_>>())
        .collect()
}


/// The field path with identifier-shaped keys kept, other keys shown as `<key>` and the offending key of an unknown field removed.
pub fn describe_path(path: &FieldPath, unknown_field: bool) -> String {
    let keep = path.iter().count().saturating_sub(usize::from(unknown_field));
    let described = path.iter().take(keep).fold(String::new(), |mut text, segment| {
        match segment {
            Segment::Seq { index } => text.push_str(&format!("[{index}]")),
            other => {
                let name = match other {
                    Segment::Map { key } => shown_key(key),
                    Segment::Enum { variant } => shown_key(variant),
                    _ => "<key>".to_string(),
                };
                text.push_str(&if text.is_empty() { name } else { format!(".{name}") });
            }
        }
        text
    });
    if described.is_empty() {
        ROOT_FIELD_PATH.to_string()
    } else {
        described
    }
}


/// Parses `text` strictly; `file` only labels errors, which carry line, column and field path but never text taken from the document.
pub fn parse_document<Document: DeserializeOwned>(text: &str, file: &str) -> Result<Document, ConfigError> {
    let options = serde_saphyr::options! { with_snippet: false };
    let mut field_path = ROOT_FIELD_PATH.to_string();
    let result = serde_saphyr::with_deserializer_from_str_with_options(text, options, |deserializer| {
        serde_path_to_error::deserialize::<_, Document>(deserializer).map_err(|error| {
            field_path = describe_path(error.path(), matches!(root_cause(error.inner()), YamlError::SerdeUnknownField { .. }));
            error.into_inner()
        })
    });
    result.map_err(|source| {
        let (line, column) = position_of(source.location());
        let message = describe_error(&source);
        ConfigError::Parse {
            file: file.to_string(),
            line,
            column,
            field_path: field_path.clone(),
            message: message.clone(),
            source: Box::new(YamlError::custom(message)),
        }
    })
}
