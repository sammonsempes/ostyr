use crate::error::OncallError;
use crate::limits::MAX_FILE_BYTES;
use crate::model::{Policy, Schedule, Silence, SilenceFile, Window, WindowFile};
use crate::validate::{validate_policy, validate_schedule, validate_silences, validate_windows};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_text};
use std::fs::File;
use std::io::Read;
use std::path::Path;


/// Reads at most `MAX_FILE_BYTES`; a longer input is refused before it is parsed.
pub fn read_limited(reader: &mut dyn Read, file: &str) -> Result<String, OncallError> {
    let text = read_text(&mut reader.take(MAX_FILE_BYTES + 1), file)?;
    if text.len() as u64 > MAX_FILE_BYTES {
        Err(OncallError::FileTooLarge {
            file: file.to_string(),
            max: MAX_FILE_BYTES,
        })
    } else {
        Ok(text)
    }
}


pub fn read_file_limited(path: &Path) -> Result<String, OncallError> {
    let file = path.display().to_string();
    let mut handle = File::open(path).map_err(|source| ConfigError::Io { file: file.clone(), source })?;
    read_limited(&mut handle, &file)
}


pub fn parse_schedule(text: &str, file: &str) -> Result<Schedule, OncallError> {
    let schedule: Schedule = parse_document(text, file)?;
    validate_schedule(&schedule)?;
    Ok(schedule)
}


pub fn parse_policy(text: &str, file: &str) -> Result<Policy, OncallError> {
    let policy: Policy = parse_document(text, file)?;
    validate_policy(&policy)?;
    Ok(policy)
}


pub fn load_schedule(path: &Path) -> Result<Schedule, OncallError> {
    parse_schedule(&read_file_limited(path)?, &path.display().to_string())
}


pub fn load_policy(path: &Path) -> Result<Policy, OncallError> {
    parse_policy(&read_file_limited(path)?, &path.display().to_string())
}


pub fn parse_silences(text: &str, file: &str) -> Result<Vec<Silence>, OncallError> {
    let parsed: SilenceFile = parse_document(text, file)?;
    validate_silences(&parsed)?;
    Ok(parsed.silences)
}


pub fn parse_windows(text: &str, file: &str) -> Result<Vec<Window>, OncallError> {
    let parsed: WindowFile = parse_document(text, file)?;
    validate_windows(&parsed)?;
    Ok(parsed.windows)
}


pub fn load_silences(path: &Path) -> Result<Vec<Silence>, OncallError> {
    parse_silences(&read_file_limited(path)?, &path.display().to_string())
}


pub fn load_windows(path: &Path) -> Result<Vec<Window>, OncallError> {
    parse_windows(&read_file_limited(path)?, &path.display().to_string())
}
