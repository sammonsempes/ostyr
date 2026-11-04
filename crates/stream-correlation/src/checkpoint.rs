use crate::error::CorrelationError;
use crate::window::State;
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::Path;


pub const CHECKPOINT_VERSION: u32 = 1;


pub const TEMPORARY_EXTENSION: &str = "tmp";


#[derive(Debug, Serialize)]
pub struct CheckpointView<'a> {
    pub version: u32,
    pub state: &'a State,
}


#[derive(Debug, Deserialize)]
pub struct Checkpoint {
    pub version: u32,
    pub state: State,
}


/// Serialises the state as one JSON document and flushes the writer.
pub fn write_checkpoint<Output: Write>(output: &mut Output, state: &State) -> Result<(), CorrelationError> {
    serde_json::to_writer(
        &mut *output,
        &CheckpointView {
            version: CHECKPOINT_VERSION,
            state,
        },
    )
    .map_err(CorrelationError::Serialize)?;
    output.flush()?;
    Ok(())
}


fn io_error(path: &Path, source: io::Error) -> CorrelationError {
    CorrelationError::CheckpointIo {
        path: path.display().to_string(),
        source,
    }
}


/// Writes `temporary`, syncs it with the injected `sync`, then renames it over `path`: a crash leaves the old or the new checkpoint, never a half one.
pub fn save_checkpoint_with(temporary: &Path, path: &Path, state: &State, sync: fn(&File) -> io::Result<()>) -> Result<(), CorrelationError> {
    let mut file = File::create(temporary).map_err(|source| io_error(temporary, source))?;
    write_checkpoint(&mut file, state)?;
    sync(&file).map_err(|source| io_error(temporary, source))?;
    fs::rename(temporary, path).map_err(|source| io_error(path, source))
}


/// Saves next to `path` through a `.tmp` sibling, with a real `fsync`.
pub fn save_checkpoint(path: &Path, state: &State) -> Result<(), CorrelationError> {
    save_checkpoint_with(&path.with_extension(TEMPORARY_EXTENSION), path, state, File::sync_all)
}


/// `None` when no checkpoint file exists yet; a file that does not parse, or has another version, is an error, never an empty state.
pub fn load_checkpoint(path: &Path) -> Result<Option<State>, CorrelationError> {
    match fs::read_to_string(path) {
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(io_error(path, source)),
        Ok(text) => {
            let checkpoint: Checkpoint = serde_json::from_str(&text).map_err(|source| CorrelationError::CorruptCheckpoint {
                path: path.display().to_string(),
                source,
            })?;
            if checkpoint.version == CHECKPOINT_VERSION {
                Ok(Some(checkpoint.state))
            } else {
                Err(CorrelationError::CheckpointVersion {
                    path: path.display().to_string(),
                    found: checkpoint.version,
                    expected: CHECKPOINT_VERSION,
                })
            }
        }
    }
}
