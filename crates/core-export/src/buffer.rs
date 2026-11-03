use crate::error::ExportError;
use crate::types::{DeliverFn, OpenFn};
use std::fs::{self, File};
use std::io::{self, Write};
use std::path::{Path, PathBuf};


pub const BATCH_EXTENSION: &str = "batch";


pub const TEMP_EXTENSION: &str = "tmp";


pub const NAME_WIDTH: usize = 20;


const NO_BYTES: u64 = 0;


const NO_BATCHES: usize = 0;


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enqueued {
    Stored(PathBuf),
    Saturated,
}


fn io_error(context: &str, path: &Path, source: io::Error) -> ExportError {
    ExportError::Io {
        context: format!("{context} {}", path.display()),
        source,
    }
}


/// Complete batch files of the buffer, oldest first (names are zero-padded counters); a missing directory is an empty buffer.
pub fn list_batches(dir: &Path) -> Result<Vec<PathBuf>, ExportError> {
    if dir.exists() {
        read_batches(dir)
    } else {
        Ok(Vec::new())
    }
}


pub fn read_batches(dir: &Path) -> Result<Vec<PathBuf>, ExportError> {
    let mut paths = fs::read_dir(dir)
        .and_then(|entries| entries.map(|entry| entry.map(|found| found.path())).collect::<io::Result<Vec<_>>>())
        .map_err(|source| io_error("read buffer", dir, source))?;
    paths.retain(|path| path.extension().is_some_and(|extension| extension == BATCH_EXTENSION));
    paths.sort();
    Ok(paths)
}


pub fn file_size(path: &Path) -> Result<u64, ExportError> {
    fs::metadata(path)
        .map(|metadata| metadata.len())
        .map_err(|source| io_error("stat", path, source))
}


pub fn batches_size(batches: &[PathBuf]) -> Result<u64, ExportError> {
    batches
        .iter()
        .try_fold(NO_BYTES, |total, path| file_size(path).map(|size| total.saturating_add(size)))
}


pub fn buffered_bytes(dir: &Path) -> Result<u64, ExportError> {
    list_batches(dir).and_then(|batches| batches_size(&batches))
}


/// The counter after the highest existing one, so new batches sort after the buffered ones.
pub fn next_counter(batches: &[PathBuf]) -> u64 {
    batches
        .iter()
        .filter_map(|path| path.file_stem().and_then(|stem| stem.to_str()).and_then(|stem| stem.parse::<u64>().ok()))
        .max()
        .map_or(0, |highest| highest.saturating_add(1))
}


pub fn write_batch<Output: Write>(out: &mut Output, body: &str) -> Result<(), ExportError> {
    out.write_all(body.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|source| ExportError::Io {
            context: "write buffered batch".to_string(),
            source,
        })
}


/// The production `OpenFn`: a new file, truncated if it exists.
pub fn create_file(path: &Path) -> io::Result<Box<dyn Write>> {
    File::create(path).map(|file| Box::new(file) as Box<dyn Write>)
}


/// Stores `body` unless the buffer would exceed `max_bytes`; written through `open` to a temporary file, then renamed.
pub fn enqueue(dir: &Path, body: &str, max_bytes: u64, open: &mut OpenFn) -> Result<Enqueued, ExportError> {
    fs::create_dir_all(dir).map_err(|source| io_error("create buffer", dir, source))?;
    let batches = list_batches(dir)?;
    let used = batches_size(&batches)?;
    if used.saturating_add(body.len() as u64) > max_bytes {
        Ok(Enqueued::Saturated)
    } else {
        let name = format!("{:0width$}", next_counter(&batches), width = NAME_WIDTH);
        let temporary = dir.join(&name).with_extension(TEMP_EXTENSION);
        let target = dir.join(&name).with_extension(BATCH_EXTENSION);
        let mut file = open(&temporary).map_err(|source| io_error("create", &temporary, source))?;
        write_batch(&mut file, body)?;
        fs::rename(&temporary, &target).map_err(|source| io_error("rename", &temporary, source))?;
        Ok(Enqueued::Stored(target))
    }
}


/// Sends buffered batches oldest first, deleting each once delivered; stops at the first failure and returns the count delivered.
pub fn drain(dir: &Path, deliver: &mut DeliverFn) -> Result<usize, ExportError> {
    list_batches(dir)?.iter().try_fold(NO_BATCHES, |count, path| {
        let body = fs::read_to_string(path).map_err(|source| io_error("read", path, source))?;
        deliver(&body)?;
        fs::remove_file(path).map_err(|source| io_error("remove", path, source))?;
        Ok(count + 1)
    })
}
