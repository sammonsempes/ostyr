use crate::dirfs::{open_read, random_bytes, write_text_atomic};
use crate::forward::{read_cursor, write_cursor};
use crate::forward_model::{EPOCH_BYTES, EPOCH_FILE, EPOCH_TEMPORARY};
use crate::types::DirHandle;
use std::io::{self, Read};


const EPOCH_FILE_MAX_BYTES: u64 = 34;


const HEX_DIGITS_PER_BYTE: usize = 2;


/// Sixteen random bytes as lower-case hex.
pub fn random_epoch() -> io::Result<String> {
    Ok(random_bytes::<EPOCH_BYTES>()?.iter().map(|byte| format!("{byte:02x}")).collect())
}


/// A fresh epoch written to the spool directory (temporary file, rename), returned.
pub fn new_epoch(dir: &DirHandle) -> io::Result<String> {
    let epoch = random_epoch()?;
    write_text_atomic(dir, EPOCH_TEMPORARY, EPOCH_FILE, &format!("{epoch}\n"))?;
    Ok(epoch)
}


/// Lower-case hex of exactly the epoch length.
pub fn valid_epoch(text: &str) -> bool {
    text.len() == EPOCH_BYTES * HEX_DIGITS_PER_BYTE && text.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}


/// The epoch of the spool directory; created when missing or malformed, refused when the file is a symlink or not a regular file.
pub fn load_epoch(dir: &DirHandle) -> io::Result<String> {
    match open_read(dir, EPOCH_FILE) {
        Ok(file) => {
            let mut text = String::new();
            file.take(EPOCH_FILE_MAX_BYTES).read_to_string(&mut text)?;
            let stored = text.trim();
            if valid_epoch(stored) {
                Ok(stored.to_owned())
            } else {
                tracing::warn!("the epoch file is malformed, a new epoch is started");
                new_epoch(dir)
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => new_epoch(dir),
        Err(error) => Err(error),
    }
}


/// The epoch at spool open: a forward cursor above the next sequence means the spool was reset (power cut), so a new epoch starts and the cursor moves down.
pub fn open_epoch(dir: &DirHandle, next_sequence: u64) -> io::Result<String> {
    let epoch = load_epoch(dir)?;
    let cursor = read_cursor(dir).unwrap_or_else(|error| {
        tracing::warn!(%error, "the forward cursor is unreadable, the epoch is kept");
        0
    });
    if cursor > next_sequence {
        let fresh = new_epoch(dir)?;
        tracing::warn!(cursor, next_sequence, epoch = %fresh, "spool behind the forward cursor, new epoch started");
        write_cursor(dir, next_sequence)?;
        Ok(fresh)
    } else {
        Ok(epoch)
    }
}
