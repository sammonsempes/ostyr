use time::macros::datetime;
use time::OffsetDateTime;


pub const NOW: OffsetDateTime = datetime!(2026-11-03 12:00:00 UTC);


pub fn now() -> OffsetDateTime {
    NOW
}
