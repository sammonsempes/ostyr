use intel_feeds::config::{FeedConfig, FeedFormat, Mapping};
use intel_feeds::model::Tlp;
use std::path::PathBuf;


pub const TEST_CONFIDENCE: u8 = 50;


pub fn feed(name: &str, format: FeedFormat) -> FeedConfig {
    FeedConfig {
        name: name.to_owned(),
        format,
        path: PathBuf::from(name),
        version: None,
        mapping: Mapping::default(),
        default_confidence: TEST_CONFIDENCE,
        tlp: Tlp::Amber,
        ttl_seconds: None,
    }
}
