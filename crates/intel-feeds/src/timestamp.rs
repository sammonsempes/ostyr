use crate::error::EntryError;
use time::format_description::well_known::Rfc3339;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime, UtcOffset};


pub const SPACED_FORMAT: &[BorrowedFormatItem<'static>] = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");


pub const UTC_SUFFIX: &str = " UTC";


/// RFC 3339 (normalised to UTC, refused when the UTC time leaves the supported range or cannot be written back as RFC 3339), or `YYYY-MM-DD HH:MM:SS` (abuse.ch) taken as UTC, with an optional ` UTC` suffix.
pub fn parse_timestamp(text: &str) -> Result<OffsetDateTime, EntryError> {
    let trimmed = text.trim().trim_end_matches(UTC_SUFFIX);
    OffsetDateTime::parse(trimmed, &Rfc3339)
        .or_else(|_rfc3339_failure| PrimitiveDateTime::parse(trimmed, SPACED_FORMAT).map(PrimitiveDateTime::assume_utc))
        .map_err(|source| EntryError::Timestamp {
            value: text.to_owned(),
            source,
        })
        .and_then(|parsed| {
            parsed
                .checked_to_offset(UtcOffset::UTC)
                .filter(|utc| utc.format(&Rfc3339).is_ok())
                .ok_or_else(|| EntryError::TimestampRange { value: text.to_owned() })
        })
}
