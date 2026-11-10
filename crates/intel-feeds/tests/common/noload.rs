use intel_feeds::config::{ClickhouseConfig, FeedConfig};
use intel_feeds::load::{LoadError, LoadOutcome};
use intel_feeds::model::Ioc;
use time::OffsetDateTime;


pub fn no_load(_config: &ClickhouseConfig, _iocs: &[Ioc], _feeds: &[FeedConfig], _now: OffsetDateTime) -> Result<LoadOutcome, LoadError> {
    Ok(LoadOutcome::default())
}
