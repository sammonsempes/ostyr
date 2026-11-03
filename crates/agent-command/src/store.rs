use crate::error::StoreError;
use crate::model::Sequences;
use crate::types::SaveFn;
use atomicwrites::{AllowOverwrite, AtomicFile, Error as AtomicError};
use std::fs;
use std::io::{self, ErrorKind, Write};
use std::path::{Path, PathBuf};


pub const ROUTINE_LABEL: &str = "routine";


pub const SENSITIVE_LABEL: &str = "sensitive";


pub fn parse_number(path: &Path, text: &str) -> Result<u64, StoreError> {
    text.parse::<u64>().map_err(|source| StoreError::Corrupt {
        path: path.to_path_buf(),
        source,
    })
}


/// One number is the old single-sequence file, read as both classes; otherwise `routine <n> sensitive <n>`.
pub fn parse_sequences(path: &Path, text: &str) -> Result<Sequences, StoreError> {
    let words: Vec<&str> = text.split_whitespace().collect();
    match words.as_slice() {
        [both] => parse_number(path, both).map(|sequence| Sequences {
            routine: sequence,
            sensitive: sequence,
        }),
        [ROUTINE_LABEL, routine, SENSITIVE_LABEL, sensitive] => Ok(Sequences {
            routine: parse_number(path, routine)?,
            sensitive: parse_number(path, sensitive)?,
        }),
        _ => Err(StoreError::Layout { path: path.to_path_buf() }),
    }
}


/// A missing file is a fresh agent (0); an unreadable or corrupt one is an error, never 0, so a replay cannot be re-accepted.
pub fn load_sequences(path: &Path) -> Result<Sequences, StoreError> {
    match fs::read_to_string(path) {
        Ok(text) => parse_sequences(path, &text),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(Sequences::default()),
        Err(source) => Err(StoreError::Io {
            path: path.to_path_buf(),
            source,
        }),
    }
}


/// `atomicwrites`: temp file in the same directory, fsync, rename, then fsync of the directory on Unix and `MoveFileExW` with write-through on Windows.
pub fn save_sequences(path: &Path, sequences: &Sequences) -> io::Result<()> {
    AtomicFile::new(path, AllowOverwrite)
        .write(|file| writeln!(file, "{ROUTINE_LABEL} {} {SENSITIVE_LABEL} {}", sequences.routine, sequences.sensitive))
        .map_err(|failure| match failure {
            AtomicError::Internal(error) | AtomicError::User(error) => error,
        })
}


pub fn file_saver(path: PathBuf) -> Box<SaveFn> {
    Box::new(move |sequences| save_sequences(&path, sequences))
}
