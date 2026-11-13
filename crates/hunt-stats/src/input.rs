use crate::error::StatsError;
use crate::types::Observation;
use std::io::Read;


/// Reads at most `max_bytes`; a longer input is refused.
pub fn read_bounded(reader: &mut dyn Read, max_bytes: u64) -> Result<String, StatsError> {
    let mut text = String::new();
    reader.take(max_bytes.saturating_add(1)).read_to_string(&mut text)?;
    if text.len() as u64 > max_bytes {
        Err(StatsError::InputTooLarge { max: max_bytes })
    } else {
        Ok(text)
    }
}


/// Parses `entity,key` lines; the key keeps any further comma. Blank lines are skipped.
pub fn parse_observations(text: &str) -> Result<Vec<Observation>, StatsError> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            line.split_once(',')
                .map(|(entity, key)| (entity.to_string(), key.to_string()))
                .ok_or(StatsError::BadLine { line: index + 1 })
        })
        .collect()
}


/// Parses one integer timestamp per line. Blank lines are skipped.
pub fn parse_timestamps(text: &str) -> Result<Vec<i64>, StatsError> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(index, line)| {
            line.trim()
                .parse::<i64>()
                .map_err(|source| StatsError::BadTimestamp { line: index + 1, source })
        })
        .collect()
}
