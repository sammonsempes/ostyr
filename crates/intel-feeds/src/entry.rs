use crate::canon::{canonicalise, detect_type, type_from_name};
use crate::config::FeedConfig;
use crate::error::EntryError;
use crate::limits::{DEFAULT_FEED_VERSION, MAX_CONFIDENCE, MAX_TAGS_PER_FIELD, MAX_TAG_BYTES};
use crate::model::{Ioc, RawEntry, Source, Tags};
use crate::sample::bounded_text;
use crate::timestamp::parse_timestamp;
use std::net::SocketAddr;
use time::{Duration, OffsetDateTime};


/// `1.2.3.4:443` and `[::1]:443` lose their port; anything else is untouched.
pub fn strip_port(value: &str) -> String {
    value
        .trim()
        .parse::<SocketAddr>()
        .map_or_else(|_not_a_socket| value.trim().to_owned(), |socket| socket.ip().to_string())
}


pub fn split_tags(field: Option<&str>) -> Vec<String> {
    field
        .unwrap_or("")
        .split(',')
        .map(str::trim)
        .filter(|tag| !tag.is_empty() && tag.len() <= MAX_TAG_BYTES)
        .take(MAX_TAGS_PER_FIELD)
        .map(str::to_owned)
        .collect()
}


pub fn time_or(text: Option<&str>, default: OffsetDateTime) -> Result<OffsetDateTime, EntryError> {
    text.map(parse_timestamp).transpose().map(|parsed| parsed.unwrap_or(default))
}


pub fn confidence_or(text: Option<&str>, default: u8) -> Result<u8, EntryError> {
    text.map(|number| {
        number
            .trim()
            .parse::<u8>()
            .map_err(|source| EntryError::Confidence {
                value: bounded_text(number),
                source: Some(source),
            })
            .and_then(|parsed| {
                if parsed <= MAX_CONFIDENCE {
                    Ok(parsed)
                } else {
                    Err(EntryError::Confidence {
                        value: bounded_text(number),
                        source: None,
                    })
                }
            })
    })
    .transpose()
    .map(|parsed| parsed.unwrap_or(default))
}


/// Builds the normalised IOC of one raw entry; a missing last-seen or first-seen is `now`, and the TTL counts from last-seen.
pub fn build_ioc(feed: &FeedConfig, raw: &RawEntry, now: OffsetDateTime) -> Result<Ioc, EntryError> {
    let value = strip_port(&raw.value);
    let declared = raw.type_name.as_deref().and_then(type_from_name).unwrap_or_else(|| detect_type(&value));
    let canonical = canonicalise(declared, &value)?;
    let first_seen = time_or(raw.first_seen.as_deref(), now)?;
    let last_seen = time_or(raw.last_seen.as_deref(), now)?;
    Ok(Ioc {
        ioc_type: canonical.ioc_type,
        value: canonical.value,
        sources: vec![Source {
            feed: feed.name.clone(),
            version: feed.version.clone().unwrap_or_else(|| DEFAULT_FEED_VERSION.to_owned()),
        }],
        first_seen,
        last_seen,
        confidence: confidence_or(raw.confidence.as_deref(), feed.default_confidence)?,
        tlp: feed.tlp,
        expires_at: feed.ttl_seconds.map(|ttl| last_seen.saturating_add(Duration::seconds(i64::from(ttl)))),
        tags: Tags {
            malware: split_tags(raw.malware.as_deref()),
            actor: split_tags(raw.actor.as_deref()),
            campaign: split_tags(raw.campaign.as_deref()),
        },
    })
}
