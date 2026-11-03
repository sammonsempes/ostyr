use super::clock::now;
use intel_feeds::config::FeedConfig;
use intel_feeds::error::FeedError;
use intel_feeds::formats::parse_feed;
use intel_feeds::model::Collector;


pub fn parse_text(config: &FeedConfig, text: &str) -> Result<Collector, FeedError> {
    parse_feed(config, &mut text.as_bytes(), now())
}
