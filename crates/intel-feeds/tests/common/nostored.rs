use intel_feeds::budget::Stored;
use intel_feeds::config::ClickhouseConfig;
use intel_feeds::read::ReadError;
use time::OffsetDateTime;


pub fn no_stored(_config: &ClickhouseConfig, _now: OffsetDateTime) -> Result<Stored, ReadError> {
    Ok(Stored::default())
}
