use crate::error::HashFileError;
use crate::model::{NtHash, MAX_HASHES, MAX_HASH_FILE_BYTES};
use crate::parse::decode_hash;
use std::io::Read;
use zeroize::Zeroizing;


/// One hex NT hash per line, LF or CRLF, blank lines skipped; the text is held in a buffer zeroed on drop.
pub fn read_hashes(reader: &mut dyn Read) -> Result<Vec<NtHash>, HashFileError> {
    let mut buffer = Zeroizing::new(Vec::new());
    reader
        .take(MAX_HASH_FILE_BYTES + 1)
        .read_to_end(&mut buffer)
        .map_err(HashFileError::Read)?;
    if buffer.len() as u64 > MAX_HASH_FILE_BYTES {
        Err(HashFileError::TooLarge)
    } else if buffer.iter().filter(|byte| **byte == b'\n').count() > MAX_HASHES {
        Err(HashFileError::TooMany)
    } else {
        buffer
            .split(|byte| *byte == b'\n')
            .enumerate()
            .filter(|(_, line)| !line.is_empty())
            .map(|(index, line)| {
                let text = line.strip_suffix(b"\r").unwrap_or(line);
                decode_hash(text).ok_or(HashFileError::Malformed { line: index + 1 })
            })
            .collect()
    }
}
