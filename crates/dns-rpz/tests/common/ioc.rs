use intel_feeds::model::{Ioc, IocType, Source, Tags, Tlp};
use time::macros::datetime;
use time::OffsetDateTime;


const FIRST_SEEN: OffsetDateTime = datetime!(2026-11-01 00:00:00 UTC);


const LAST_SEEN: OffsetDateTime = datetime!(2026-11-03 00:00:00 UTC);


pub fn ioc(ioc_type: IocType, value: &str, confidence: u8, tlp: Tlp) -> Ioc {
    Ioc {
        ioc_type,
        value: value.to_owned(),
        sources: vec![Source {
            feed: "test".to_owned(),
            version: "1".to_owned(),
        }],
        first_seen: FIRST_SEEN,
        last_seen: LAST_SEEN,
        confidence,
        tlp,
        expires_at: None,
        tags: Tags::default(),
    }
}
