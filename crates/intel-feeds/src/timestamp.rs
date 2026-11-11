use crate::error::EntryError;
use crate::sample::bounded_text;
use time::format_description::well_known::Rfc3339;
use time::format_description::BorrowedFormatItem;
use time::macros::format_description;
use time::{OffsetDateTime, PrimitiveDateTime};


pub const SPACED_FORMAT: &[BorrowedFormatItem<'static>] = format_description!("[year]-[month]-[day] [hour]:[minute]:[second]");


pub const UTC_SUFFIX: &str = " UTC";


/// RFC 3339, or `YYYY-MM-DD HH:MM:SS` (abuse.ch) taken as UTC, with an optional ` UTC` suffix.
pub fn parse_timestamp(text: &str) -> Result<OffsetDateTime, EntryError> {
    let trimmed = text.trim().trim_end_matches(UTC_SUFFIX);
    OffsetDateTime::parse(trimmed, &Rfc3339)
        .or_else(|_rfc3339_failure| PrimitiveDateTime::parse(trimmed, SPACED_FORMAT).map(PrimitiveDateTime::assume_utc))
        .map_err(|source| EntryError::Timestamp {
            value: bounded_text(text),
            source,
        })
}
