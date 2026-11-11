use crate::config::FeedConfig;
use crate::entry::build_ioc;
use crate::error::{EntryError, FeedError};
use crate::formats::{parse_items, read_document, value_text};
use crate::limits::MAX_MISP_ATTRIBUTES;
use crate::model::{Collector, Ioc, RawEntry, Tlp};
use serde_json::{Map, Value};
use std::cell::Cell;
use std::io::BufRead;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


pub const TLP_PREFIX: &str = "tlp:";


/// The strictest TLP of some tags; `known` is false when a `tlp:` tag was not understood (the level is then `Red`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TlpReading {
    pub tlp: Tlp,
    pub known: bool,
}


/// One IOC candidate of an attribute: the type name `build_ioc` understands and the text to validate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Part<'a> {
    pub type_name: &'static str,
    pub value: &'a str,
}


pub const NO_TLP: TlpReading = TlpReading {
    tlp: Tlp::Clear,
    known: true,
};


pub const BAD_TLP: TlpReading = TlpReading { tlp: Tlp::Red, known: false };


pub fn strictest(first: TlpReading, second: TlpReading) -> TlpReading {
    TlpReading {
        tlp: first.tlp.max(second.tlp),
        known: first.known && second.known,
    }
}


pub fn known_level(tlp: Tlp) -> TlpReading {
    TlpReading { tlp, known: true }
}


/// `None` when the tag is not a `tlp:` tag; an unknown level reads as `Red`.
pub fn tlp_of_tag(name: &str) -> Option<TlpReading> {
    let lowered = name.trim().to_ascii_lowercase();
    lowered.strip_prefix(TLP_PREFIX).map(|level| match level.trim() {
        "clear" | "white" => known_level(Tlp::Clear),
        "green" => known_level(Tlp::Green),
        "amber" => known_level(Tlp::Amber),
        "amber+strict" => known_level(Tlp::AmberStrict),
        "red" => known_level(Tlp::Red),
        _ => BAD_TLP,
    })
}


/// `tags` is the MISP `Tag` field: an array of `{"name": ...}`; any other shape is fail-closed.
pub fn tags_tlp(tags: Option<&Value>) -> TlpReading {
    match tags {
        None | Some(Value::Null) => NO_TLP,
        Some(Value::Array(list)) => list
            .iter()
            .filter_map(|tag| tag.get("name").and_then(Value::as_str))
            .filter_map(tlp_of_tag)
            .fold(NO_TLP, strictest),
        Some(_) => BAD_TLP,
    }
}


/// `true`, `1` and `"1"` or `"true"`; anything else, an absent field included, is false.
pub fn flag(object: &Map<String, Value>, name: &str) -> bool {
    match object.get(name) {
        Some(Value::Bool(set)) => *set,
        Some(Value::String(text)) => text == "1" || text.eq_ignore_ascii_case("true"),
        Some(Value::Number(number)) => number.as_u64() == Some(1),
        _ => false,
    }
}


pub fn part<'a>(type_name: &'static str, value: &'a str) -> Part<'a> {
    Part { type_name, value }
}


/// A value with a `/` is a network, else the address decides between IPv4 and IPv6; a hostname never passes as an address.
pub fn ip_part(value: &str) -> Part<'_> {
    if value.contains('/') {
        part("cidr", value)
    } else {
        part("ipv4", value)
    }
}


/// The fixed MISP type table; `None` for every other type. A missing half of a composite type is empty, so it fails validation.
pub fn misp_parts<'a>(kind: &str, value: &'a str) -> Option<Vec<Part<'a>>> {
    let (head, tail) = value.split_once('|').unwrap_or((value, ""));
    let hash = value.rsplit_once('|').map_or("", |(_name, digest)| digest);
    match kind {
        "ip-src" | "ip-dst" => Some(vec![ip_part(value)]),
        "ip-src|port" | "ip-dst|port" => Some(vec![ip_part(head)]),
        "domain" | "hostname" => Some(vec![part("domain", value)]),
        "domain|ip" => Some(vec![part("domain", head), ip_part(tail)]),
        "url" => Some(vec![part("url", value)]),
        "md5" => Some(vec![part("md5", value)]),
        "sha1" => Some(vec![part("sha1", value)]),
        "sha256" => Some(vec![part("sha256", value)]),
        "filename|md5" => Some(vec![part("md5", hash)]),
        "filename|sha1" => Some(vec![part("sha1", hash)]),
        "filename|sha256" => Some(vec![part("sha256", hash)]),
        _ => None,
    }
}


/// Unix seconds as RFC 3339; any other text is returned unchanged so the shared time parsing refuses it.
pub fn unix_as_rfc3339(text: &str) -> String {
    text.trim()
        .parse::<i64>()
        .ok()
        .and_then(|seconds| OffsetDateTime::from_unix_timestamp(seconds).ok())
        .and_then(|moment| moment.format(&Rfc3339).ok())
        .unwrap_or_else(|| text.to_owned())
}


/// One attribute to its IOCs. The attribute's tags raise the TLP, never lower it; the second value is whether a TLP tag was unknown.
pub fn attribute_iocs(
    feed: &FeedConfig,
    now: OffsetDateTime,
    event: TlpReading,
    object: &Map<String, Value>,
) -> Result<(Vec<Ioc>, bool), EntryError> {
    let text = |name: &str| object.get(name).and_then(value_text);
    let kind = text("type").ok_or(EntryError::MissingField("type"))?;
    let value = text("value").ok_or(EntryError::MissingField("value"))?;
    let parts = misp_parts(&kind, &value).ok_or(EntryError::UnsupportedPattern)?;
    if value.chars().any(char::is_control) {
        Err(EntryError::ControlCharacter)
    } else {
        let reading = strictest(event, tags_tlp(object.get("Tag")));
        let stamp = text("timestamp").map(|seconds| unix_as_rfc3339(&seconds));
        let iocs = parts
            .iter()
            .map(|candidate| {
                let raw = RawEntry {
                    value: candidate.value.to_owned(),
                    type_name: Some(candidate.type_name.to_owned()),
                    first_seen: text("first_seen").or_else(|| stamp.clone()),
                    last_seen: text("last_seen").or_else(|| stamp.clone()),
                    ..RawEntry::default()
                };
                build_ioc(feed, &raw, now).map(|ioc| Ioc {
                    tlp: ioc.tlp.max(reading.tlp),
                    ..ioc
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok((iocs, !reading.known))
    }
}


/// `unknown` counts the items whose event or attribute carried an unknown `tlp:` tag.
pub fn misp_item(feed: &FeedConfig, now: OffsetDateTime, event: TlpReading, unknown: &Cell<u64>, attribute: &Value) -> Result<Vec<Ioc>, EntryError> {
    let object = attribute.as_object().ok_or(EntryError::NotAnObject)?;
    if flag(object, "deleted") {
        Err(EntryError::Deleted)
    } else if !flag(object, "to_ids") {
        Err(EntryError::NotForDetection)
    } else {
        attribute_iocs(feed, now, event, object).map(|(iocs, unreadable)| {
            unknown.set(unknown.get() + u64::from(unreadable));
            iocs
        })
    }
}


/// An absent or null field is empty; anything but an array is not an event.
pub fn array_field<'a>(parent: &'a Value, name: &str) -> Result<&'a [Value], FeedError> {
    match parent.get(name) {
        None | Some(Value::Null) => Ok(&[]),
        Some(Value::Array(items)) => Ok(items),
        Some(_) => Err(FeedError::NotAnEvent),
    }
}


/// `Event.Attribute` then each `Event.Object[].Attribute`, counted before anything is copied.
pub fn event_attributes(event: &Value) -> Result<Vec<Value>, FeedError> {
    let direct = array_field(event, "Attribute")?;
    let nested = array_field(event, "Object")?
        .iter()
        .map(|object| array_field(object, "Attribute"))
        .collect::<Result<Vec<_>, _>>()?;
    let total = direct.len() + nested.iter().map(|attributes| attributes.len()).sum::<usize>();
    if total > MAX_MISP_ATTRIBUTES {
        Err(FeedError::TooManyAttributes)
    } else {
        Ok(direct.iter().chain(nested.into_iter().flatten()).cloned().collect())
    }
}


/// One MISP event file; the feed's TLP is the floor, event and attribute `tlp:` tags can only raise it.
pub fn parse_misp(feed: &FeedConfig, reader: &mut dyn BufRead, now: OffsetDateTime) -> Result<Collector, FeedError> {
    let document = read_document(reader)?;
    let event = document
        .get("Event")
        .filter(|candidate| candidate.is_object())
        .ok_or(FeedError::NotAnEvent)?;
    let attributes = event_attributes(event)?;
    let reading = tags_tlp(event.get("Tag"));
    let unknown = Cell::new(0);
    let mut collector = parse_items(feed, &attributes, &|attribute| misp_item(feed, now, reading, &unknown, attribute));
    collector.summary.unknown_tlp = unknown.get();
    Ok(collector)
}
