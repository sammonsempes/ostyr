use crate::config::FeedConfig;
use crate::entry::build_ioc;
use crate::error::{EntryError, FeedError};
use crate::formats::{flag_empty, json_failure, list_error, opening, parse_raw_items, read_document, root_value, value_of, value_text};
use crate::limits::{MAX_MISP_ATTRIBUTES, MAX_MISP_OBJECTS, MAX_MISP_TAGS, MAX_OBJECT_BYTES};
use crate::model::{Collector, Ioc, RawEntry, Tlp};
use crate::scan::raw_elements;
use crate::types::Tagged;
use serde::Deserialize;
use serde_json::value::RawValue;
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


/// `tags` is the MISP `Tag` field: an array of `{"name": ...}` (over `MAX_MISP_TAGS` it reads `Red`); any other shape is fail-closed.
pub fn tags_tlp(tags: Option<&Value>) -> TlpReading {
    match tags {
        None | Some(Value::Null) => NO_TLP,
        Some(Value::Array(list)) if list.len() <= MAX_MISP_TAGS => list
            .iter()
            .filter_map(|tag| tag.get("name").and_then(Value::as_str))
            .filter_map(tlp_of_tag)
            .fold(NO_TLP, strictest),
        Some(_) => BAD_TLP,
    }
}


/// Fails closed: not set only when absent, `false`, `0`, `"0"` or `"false"`; any other value reads as set.
pub fn flag_fails_to_true(object: &Map<String, Value>, name: &str) -> bool {
    match object.get(name) {
        None | Some(Value::Bool(false)) => false,
        Some(Value::String(text)) => !(text == "0" || text.eq_ignore_ascii_case("false")),
        Some(Value::Number(number)) => number.as_u64() != Some(0),
        Some(_) => true,
    }
}


/// Fails safe: only `true`, `1`, `"1"` or `"true"` is set; anything else, an absent field included, is not.
pub fn flag_fails_to_false(object: &Map<String, Value>, name: &str) -> bool {
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


/// `unknown` counts the items whose event, object or attribute carried an unknown `tlp:` tag.
pub fn misp_item(feed: &FeedConfig, now: OffsetDateTime, event: TlpReading, unknown: &Cell<u64>, attribute: &Value) -> Result<Vec<Ioc>, EntryError> {
    let object = attribute.as_object().ok_or(EntryError::NotAnObject)?;
    if flag_fails_to_true(object, "deleted") {
        Err(EntryError::Deleted)
    } else if !flag_fails_to_false(object, "to_ids") {
        Err(EntryError::NotForDetection)
    } else {
        attribute_iocs(feed, now, event, object).map(|(iocs, unreadable)| {
            unknown.set(unknown.get() + u64::from(unreadable));
            iocs
        })
    }
}


#[derive(Deserialize)]
pub struct Document<'a> {
    #[serde(default, borrow, rename = "Event")]
    pub event: Option<&'a RawValue>,
}


/// The three fields read of an event and of an object; everything else is skipped unmaterialised.
#[derive(Deserialize)]
pub struct Parts<'a> {
    #[serde(default, borrow, rename = "Attribute")]
    pub attribute: Option<&'a RawValue>,
    #[serde(default, borrow, rename = "Object")]
    pub object: Option<&'a RawValue>,
    #[serde(default, borrow, rename = "Tag")]
    pub tag: Option<&'a RawValue>,
}


/// Every attribute of the event with its TLP floor, and the objects that could not be read.
#[derive(Default)]
pub struct Gathered<'a> {
    pub items: Vec<Tagged<'a>>,
    pub bad_objects: u64,
}


pub const BAD_OBJECT: &str = "bad_object";


/// One tag: over `MAX_OBJECT_BYTES` or unreadable it reads `Red`, never a prefix.
pub fn raw_tag_tlp(tag: &RawValue) -> TlpReading {
    match value_of(tag.get()) {
        Ok(value) => value.get("name").and_then(Value::as_str).and_then(tlp_of_tag).unwrap_or(NO_TLP),
        Err(_) => BAD_TLP,
    }
}


/// The event or object `Tag` list: over `MAX_MISP_TAGS`, or not a list, it reads `Red` (`unknown_tlp`).
pub fn raw_tags_tlp(raw: Option<&RawValue>) -> TlpReading {
    raw.map_or(NO_TLP, |tags| {
        raw_elements(tags, MAX_MISP_TAGS).map_or(BAD_TLP, |list| list.iter().map(|tag| raw_tag_tlp(tag)).fold(NO_TLP, strictest))
    })
}


/// An absent field is empty; anything but a list is not an event.
pub fn event_list(raw: Option<&RawValue>, cap: usize, over: FeedError) -> Result<Vec<&RawValue>, FeedError> {
    raw.map_or(Ok(Vec::new()), |list| {
        let opened = opening(list, '[').ok_or(FeedError::NotAnEvent)?;
        raw_elements(opened, cap).map_err(|error| list_error(error, over))
    })
}


/// One object's attributes join the list under the attribute room left; an unreadable object is counted, not fatal.
pub fn add_object<'a>(mut gathered: Gathered<'a>, object: &'a RawValue, event: TlpReading) -> Result<Gathered<'a>, FeedError> {
    match readable_object(object) {
        None => Ok(Gathered {
            bad_objects: gathered.bad_objects + 1,
            ..gathered
        }),
        Some((list, reading)) => {
            let room = MAX_MISP_ATTRIBUTES.saturating_sub(gathered.items.len());
            let attributes = list.map_or(Ok(Vec::new()), |attributes| {
                raw_elements(attributes, room).map_err(|error| list_error(error, FeedError::TooManyAttributes))
            })?;
            let floor = strictest(event, reading);
            gathered.items.extend(attributes.into_iter().map(|attribute| (attribute, floor)));
            Ok(gathered)
        }
    }
}


/// An object that is a JSON object whose own text (its attributes apart) is within `MAX_OBJECT_BYTES` and whose `Attribute` is a list or absent.
pub fn readable_object(object: &RawValue) -> Option<(Option<&RawValue>, TlpReading)> {
    match serde_json::from_str::<Parts>(object.get()) {
        Ok(parts) => {
            let attribute_bytes = parts.attribute.map_or(0, |list| list.get().len());
            let readable = object.get().starts_with('{')
                && object.get().len().saturating_sub(attribute_bytes) <= MAX_OBJECT_BYTES
                && parts.attribute.is_none_or(|list| list.get().starts_with('['));
            readable.then(|| (parts.attribute, raw_tags_tlp(parts.tag)))
        }
        Err(_) => None,
    }
}


/// The event's own attributes, then those of each object, all counted against `MAX_MISP_ATTRIBUTES` before they are listed.
pub fn gather<'a>(event: &Parts<'a>, reading: TlpReading) -> Result<Gathered<'a>, FeedError> {
    let direct = event_list(event.attribute, MAX_MISP_ATTRIBUTES, FeedError::TooManyAttributes)?;
    let objects = event_list(event.object, MAX_MISP_OBJECTS, FeedError::TooManyObjects)?;
    let start = Gathered {
        items: direct.into_iter().map(|attribute| (attribute, reading)).collect(),
        bad_objects: 0,
    };
    objects
        .into_iter()
        .try_fold(start, |gathered, object| add_object(gathered, object, reading))
}


/// One MISP event file; the feed's TLP is the floor, event, object and attribute `tlp:` tags can only raise it.
pub fn parse_misp(feed: &FeedConfig, reader: &mut dyn BufRead, now: OffsetDateTime) -> Result<Collector, FeedError> {
    let bytes = read_document(reader)?;
    let root = opening(root_value(&bytes)?, '{').ok_or(FeedError::NotAnEvent)?;
    let document: Document = serde_json::from_str(root.get()).map_err(|error| json_failure(&error))?;
    let event_text = document.event.and_then(|event| opening(event, '{')).ok_or(FeedError::NotAnEvent)?;
    let event: Parts = serde_json::from_str(event_text.get()).map_err(|error| json_failure(&error))?;
    let gathered = gather(&event, raw_tags_tlp(event.tag))?;
    let unknown = Cell::new(0);
    let mut collector = parse_raw_items(feed, &gathered.items, &|attribute, floor| {
        misp_item(feed, now, floor, &unknown, attribute)
    })?;
    collector.summary.unknown_tlp = unknown.get();
    if gathered.bad_objects > 0 {
        collector.summary.skipped.insert(BAD_OBJECT, gathered.bad_objects);
    }
    Ok(flag_empty(collector))
}
