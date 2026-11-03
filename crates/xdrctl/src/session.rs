use crate::error::CliError;
use crate::model::Session;
use core_audit::log::owner_only;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};


pub const SESSION_FILE_NAME: &str = "session.json";


pub fn session_path(config_dir: &Path) -> PathBuf {
    config_dir.join(SESSION_FILE_NAME)
}


pub fn ignore_missing(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}


pub fn session_error(path: &Path) -> impl FnOnce(io::Error) -> CliError + '_ {
    move |source| CliError::Session {
        path: path.to_path_buf(),
        source,
    }
}


/// Writes the session file readable by its owner only; an older file is removed first so that its mode never carries over.
pub fn save_session(path: &Path, session: &Session) -> Result<(), CliError> {
    let text = serde_json::to_string(session)?;
    path.parent()
        .map_or(Ok(()), fs::create_dir_all)
        .and_then(|()| ignore_missing(fs::remove_file(path)))
        .and_then(|()| owner_only(OpenOptions::new().write(true).create_new(true)).open(path))
        .and_then(|mut file| file.write_all(text.as_bytes()))
        .map_err(session_error(path))
}


pub fn load_session(path: &Path) -> Result<Session, CliError> {
    match fs::read(path) {
        Ok(bytes) => serde_json::from_slice(&bytes).map_err(|source| CliError::SessionFormat {
            path: path.to_path_buf(),
            source,
        }),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Err(CliError::NotLoggedIn),
        Err(error) => Err(session_error(path)(error)),
    }
}


pub fn remove_session(path: &Path) -> Result<(), CliError> {
    ignore_missing(fs::remove_file(path)).map_err(session_error(path))
}
