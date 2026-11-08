//! OSV record parsing, bounded in size and count before anything is parsed.

use crate::error::OsvError;
use crate::limits::{
    MAX_AFFECTED_PER_RECORD, MAX_EVENTS_PER_RANGE, MAX_RANGES_PER_AFFECTED, MAX_RECORDS, MAX_RECORD_BYTES, MAX_VERSIONS_PER_AFFECTED,
};
use crate::model::{Affected, OsvRecord};


pub fn parse_record(text: &str) -> Result<OsvRecord, OsvError> {
    (text.len() <= MAX_RECORD_BYTES).then_some(()).ok_or(OsvError::TooLarge {
        size: text.len(),
        max: MAX_RECORD_BYTES,
    })?;
    let record: OsvRecord = serde_json::from_str(text)?;
    check_count("affected entries", record.affected.len(), MAX_AFFECTED_PER_RECORD)?;
    record.affected.iter().try_for_each(check_affected)?;
    Ok(record)
}


pub fn parse_records(texts: &[&str]) -> Result<Vec<OsvRecord>, OsvError> {
    check_count("records", texts.len(), MAX_RECORDS)?;
    texts.iter().map(|text| parse_record(text)).collect()
}


fn check_affected(affected: &Affected) -> Result<(), OsvError> {
    check_count("ranges per affected entry", affected.ranges.len(), MAX_RANGES_PER_AFFECTED)?;
    check_count("versions per affected entry", affected.versions.len(), MAX_VERSIONS_PER_AFFECTED)?;
    affected
        .ranges
        .iter()
        .try_for_each(|range| check_count("events per range", range.events.len(), MAX_EVENTS_PER_RANGE))
}


fn check_count(what: &'static str, count: usize, max: usize) -> Result<(), OsvError> {
    (count <= max).then_some(()).ok_or(OsvError::TooMany { what, count, max })
}
