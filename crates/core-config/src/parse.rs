use crate::error::ConfigError;
use serde::de::DeserializeOwned;
use serde_saphyr::Location;
use std::fs::File;
use std::io::Read;
use std::path::Path;


pub const ROOT_FIELD_PATH: &str = ".";


pub fn read_text(reader: &mut dyn Read, file: &str) -> Result<String, ConfigError> {
    let mut text = String::new();
    reader.read_to_string(&mut text).map_err(|source| ConfigError::Io {
        file: file.to_string(),
        source,
    })?;
    Ok(text)
}


pub fn read_file(path: &Path) -> Result<String, ConfigError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    read_text(&mut handle, &file)
}


/// Line and column of a parser location, `(0, 0)` when the parser gave none.
pub fn position_of(location: Option<Location>) -> (u64, u64) {
    location.map_or((0, 0), |known| (known.line(), known.column()))
}


/// Parses `text` strictly; `file` only labels errors, which carry line, column and field path.
pub fn parse_document<Document: DeserializeOwned>(text: &str, file: &str) -> Result<Document, ConfigError> {
    let options = serde_saphyr::options! { with_snippet: false };
    let mut field_path = ROOT_FIELD_PATH.to_string();
    let result = serde_saphyr::with_deserializer_from_str_with_options(text, options, |deserializer| {
        serde_path_to_error::deserialize::<_, Document>(deserializer).map_err(|error| {
            field_path = error.path().to_string();
            error.into_inner()
        })
    });
    result.map_err(|source| {
        let (line, column) = position_of(source.location());
        ConfigError::Parse {
            file: file.to_string(),
            line,
            column,
            field_path: field_path.clone(),
            message: source.to_string(),
            source: Box::new(source),
        }
    })
}
