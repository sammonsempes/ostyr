use crate::model::{Channel, CursorState, MAX_CURSOR_BYTES, MAX_RECORD_ID, MAX_TIME_BYTES};
use std::fs::{rename, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};


const TIME_EXTRA: &str = "-:.";


pub fn cursor_path(state_dir: &Path, channel: &Channel) -> PathBuf {
    state_dir.join(channel.cursor_file)
}


pub fn is_time_text(text: &str) -> bool {
    !text.is_empty() && text.len() <= MAX_TIME_BYTES && text.chars().all(|found| found.is_ascii_alphanumeric() || TIME_EXTRA.contains(found))
}


pub fn parse_record_id(text: &str) -> Option<u64> {
    let plain = !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()) && !text.starts_with('0');
    plain.then(|| text.parse::<u64>().ok()).flatten().filter(|id| *id <= MAX_RECORD_ID)
}


pub fn parse_cursor(bytes: &[u8]) -> CursorState {
    let within = u64::try_from(bytes.len()).is_ok_and(|length| length <= MAX_CURSOR_BYTES);
    let parsed = std::str::from_utf8(bytes).ok().filter(|_| within).and_then(|text| {
        let body = text.strip_suffix('\n').unwrap_or(text);
        body.split_once(' ')
            .filter(|(_, time)| is_time_text(time))
            .and_then(|(id, time)| parse_record_id(id).map(|record_id| (record_id, time.to_string())))
    });
    parsed.map_or(CursorState::Invalid, |(record_id, time)| CursorState::Valid { record_id, time })
}


pub fn read_cursor(state_dir: &Path, channel: &Channel) -> io::Result<CursorState> {
    match File::open(cursor_path(state_dir, channel)) {
        Ok(file) => {
            let mut bytes = Vec::new();
            file.take(MAX_CURSOR_BYTES + 1).read_to_end(&mut bytes)?;
            Ok(parse_cursor(&bytes))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(CursorState::Missing),
        Err(error) => Err(error),
    }
}


pub fn write_cursor(state_dir: &Path, channel: &Channel, record_id: u64, time: &str) -> io::Result<()> {
    let path = cursor_path(state_dir, channel);
    let temporary = state_dir.join(format!("{}.tmp", channel.cursor_file));
    let mut file = File::create(&temporary)?;
    writeln!(file, "{record_id} {time}")?;
    file.sync_all()?;
    rename(&temporary, &path)
}
