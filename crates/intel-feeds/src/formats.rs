use crate::config::{FeedConfig, FeedFormat, Mapping};
use crate::entry::build_ioc;
use crate::error::{reason_key, EntryError, FeedError};
use crate::limits::{MAX_DOCUMENT_BYTES, MAX_DOCUMENT_ITEMS, MAX_FEED_IOCS, MAX_OBJECT_BYTES, MAX_REPORTED_SKIPS, MAX_STIX_OBJECTS};
use crate::lines::numbered_lines;
use crate::misp::{parse_misp, NO_TLP};
use crate::model::{Collector, FeedSummary, Ioc, RawEntry, SkipSample};
use crate::sample::bounded_text;
use crate::scan::{raw_elements, ScanError};
use crate::stix::parse_pattern;
use crate::types::{ItemHandler, LineHandler, Tagged};
use csv::StringRecord;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::{Map, Value};
use std::io::{BufRead, Read};
use time::OffsetDateTime;
use tracing::debug;


pub const URLHAUS_HEADER: [&str; 9] = [
    "id",
    "dateadded",
    "url",
    "url_status",
    "last_online",
    "threat",
    "tags",
    "urlhaus_link",
    "reporter",
];


pub const THREATFOX_HEADER: [&str; 15] = [
    "first_seen_utc",
    "ioc_id",
    "ioc_value",
    "ioc_type",
    "threat_type",
    "fk_malware",
    "malware_alias",
    "malware_printable",
    "last_seen_utc",
    "confidence_level",
    "is_compromised",
    "reference",
    "tags",
    "anonymous",
    "reporter",
];


pub const FEODO_HEADER: [&str; 6] = ["first_seen_utc", "dst_ip", "dst_port", "c2_status", "last_online", "malware"];


pub const COMMENT_PREFIX: char = '#';


pub const STIX_INDICATOR: &str = "indicator";


pub const EMPTY_DOCUMENT: &str = "empty_document";


pub fn named(value: &str) -> Option<String> {
    Some(value.to_owned())
}


pub fn urlhaus_mapping() -> Mapping {
    Mapping {
        value: named("url"),
        first_seen: named("dateadded"),
        malware: named("tags"),
        ..Mapping::default()
    }
}


pub fn threatfox_mapping() -> Mapping {
    Mapping {
        value: named("ioc_value"),
        ioc_type: named("ioc_type"),
        first_seen: named("first_seen_utc"),
        last_seen: named("last_seen_utc"),
        confidence: named("confidence_level"),
        malware: named("malware_printable"),
        ..Mapping::default()
    }
}


pub fn feodo_mapping() -> Mapping {
    Mapping {
        value: named("dst_ip"),
        first_seen: named("first_seen_utc"),
        malware: named("malware"),
        ..Mapping::default()
    }
}


/// Fixed column names and mapping of the abuse.ch CSV exports; `None` for the other formats.
pub fn abusech_layout(format: FeedFormat) -> Option<(Vec<String>, Mapping)> {
    let layout: Option<(&[&str], Mapping)> = match format {
        FeedFormat::AbuseChUrlhaus => Some((&URLHAUS_HEADER, urlhaus_mapping())),
        FeedFormat::AbuseChThreatfox => Some((&THREATFOX_HEADER, threatfox_mapping())),
        FeedFormat::AbuseChFeodo => Some((&FEODO_HEADER, feodo_mapping())),
        FeedFormat::Stix | FeedFormat::Crowdsec | FeedFormat::Csv | FeedFormat::Json | FeedFormat::Misp | FeedFormat::Taxii21 => None,
    };
    layout.map(|(header, mapping)| (header.iter().map(|name| (*name).to_owned()).collect(), mapping))
}


pub fn new_collector(feed: &FeedConfig) -> Collector {
    Collector {
        iocs: Vec::new(),
        summary: FeedSummary {
            feed: feed.name.clone(),
            ..FeedSummary::default()
        },
    }
}


/// Counts one outcome: parsed IOCs are kept, an unsupported pattern is counted apart, anything else is a skip with a reason.
pub fn record(collector: &mut Collector, line: u64, outcome: Result<Vec<Ioc>, EntryError>) {
    match outcome {
        Ok(iocs) => {
            collector.summary.parsed += iocs.len() as u64;
            collector.iocs.extend(iocs);
        }
        Err(EntryError::UnsupportedPattern) => collector.summary.unsupported += 1,
        Err(error) => {
            *collector.summary.skipped.entry(reason_key(&error)).or_insert(0) += 1;
            let reason = bounded_text(&error.to_string());
            debug!(feed = collector.summary.feed, line, %reason, "entry skipped");
            if collector.summary.samples.len() < MAX_REPORTED_SKIPS {
                collector.summary.samples.push(SkipSample { line, reason });
            }
        }
    }
}


/// `record` after the count: an outcome that would take the feed over `MAX_FEED_IOCS` fails the feed before its IOCs are kept.
pub fn record_bounded(collector: &mut Collector, line: u64, outcome: Result<Vec<Ioc>, EntryError>) -> Result<(), FeedError> {
    let over = outcome
        .as_ref()
        .is_ok_and(|iocs| collector.iocs.len().saturating_add(iocs.len()) > MAX_FEED_IOCS);
    if over {
        Err(FeedError::TooManyIocs)
    } else {
        record(collector, line, outcome);
        Ok(())
    }
}


pub fn ignorable(text: &str) -> bool {
    let trimmed = text.trim();
    trimmed.is_empty() || trimmed.starts_with(COMMENT_PREFIX)
}


pub fn line_outcome(feed: &FeedConfig, now: OffsetDateTime, handler: &mut LineHandler, text: &str) -> Result<Vec<Ioc>, EntryError> {
    if ignorable(text) {
        Ok(Vec::new())
    } else {
        handler(text)?
            .map(|raw| build_ioc(feed, &raw, now))
            .transpose()
            .map(|ioc| ioc.into_iter().collect())
    }
}


/// Line-oriented feeds; blank and `#` lines are ignored, an over-long or non-UTF-8 line is a skip.
pub fn parse_lines(feed: &FeedConfig, reader: &mut dyn BufRead, now: OffsetDateTime, handler: &mut LineHandler) -> Result<Collector, FeedError> {
    let mut collector = new_collector(feed);
    numbered_lines(reader).try_for_each(|line| {
        let numbered = line?;
        let outcome = numbered.text.and_then(|text| line_outcome(feed, now, handler, &text));
        record_bounded(&mut collector, numbered.number, outcome)
    })?;
    Ok(collector)
}


pub fn csv_record(source: &mut dyn Read) -> Result<StringRecord, EntryError> {
    let mut reader = csv::ReaderBuilder::new().has_headers(false).flexible(true).from_reader(source);
    let mut record = StringRecord::new();
    reader.read_record(&mut record).map_err(EntryError::Csv)?;
    Ok(record)
}


pub fn csv_field(header: &[String], record: &StringRecord, name: Option<&str>) -> Option<String> {
    name.and_then(|column| header.iter().position(|candidate| candidate == column))
        .and_then(|index| record.get(index))
        .map(|field| field.trim().trim_matches('"').trim())
        .filter(|field| !field.is_empty())
        .map(str::to_owned)
}


pub fn value_text(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(text.trim().to_owned()),
        Value::Number(number) => Some(number.to_string()),
        Value::Array(items) => Some(items.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(",")),
        Value::Null | Value::Bool(_) | Value::Object(_) => None,
    }
    .filter(|text| !text.is_empty())
}


/// `fetch` returns the text of the column or field named in the mapping.
pub fn raw_entry(mapping: &Mapping, fetch: &dyn Fn(Option<&str>) -> Option<String>) -> Result<RawEntry, EntryError> {
    let value = fetch(mapping.value.as_deref()).ok_or(EntryError::MissingField("value"))?;
    Ok(RawEntry {
        value,
        type_name: fetch(mapping.ioc_type.as_deref()),
        first_seen: fetch(mapping.first_seen.as_deref()),
        last_seen: fetch(mapping.last_seen.as_deref()),
        confidence: fetch(mapping.confidence.as_deref()),
        malware: fetch(mapping.malware.as_deref()),
        actor: fetch(mapping.actor.as_deref()),
        campaign: fetch(mapping.campaign.as_deref()),
    })
}


/// Generic CSV starts without a header: the first data line names the columns. abuse.ch layouts are fixed.
pub fn parse_csv(feed: &FeedConfig, reader: &mut dyn BufRead, now: OffsetDateTime) -> Result<Collector, FeedError> {
    let (mut header, mapping) = abusech_layout(feed.format).map_or_else(|| (None, feed.mapping.clone()), |(names, fixed)| (Some(names), fixed));
    parse_lines(feed, reader, now, &mut |text| {
        let record = csv_record(&mut text.as_bytes())?;
        match &header {
            Some(names) => raw_entry(&mapping, &|name| csv_field(names, &record, name)).map(Some),
            None => {
                header = Some(record.iter().map(|column| column.trim().to_owned()).collect());
                Ok(None)
            }
        }
    })
}


pub fn parse_crowdsec(feed: &FeedConfig, reader: &mut dyn BufRead, now: OffsetDateTime) -> Result<Collector, FeedError> {
    parse_lines(feed, reader, now, &mut |text| {
        Ok(Some(RawEntry {
            value: text.trim().to_owned(),
            ..RawEntry::default()
        }))
    })
}


/// The document's bytes, at most `MAX_DOCUMENT_BYTES`; nothing is parsed here.
pub fn read_document(reader: &mut dyn BufRead) -> Result<Vec<u8>, FeedError> {
    let mut bytes = Vec::new();
    Read::take(&mut *reader, MAX_DOCUMENT_BYTES as u64 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        Err(FeedError::DocumentTooLarge)
    } else {
        Ok(bytes)
    }
}


/// Category, line and column only: serde's own text repeats the offending value, which is feed text.
pub fn json_failure(error: &serde_json::Error) -> FeedError {
    FeedError::Json {
        category: error.classify(),
        line: error.line(),
        column: error.column(),
    }
}


/// A scan error as a feed error; `over` is the named failure of the list that was too long.
pub fn list_error(error: ScanError, over: FeedError) -> FeedError {
    match error {
        ScanError::TooMany => over,
        ScanError::Json { category, line, column } => FeedError::Json { category, line, column },
    }
}


/// The whole document as raw text, syntax checked and nothing materialised.
pub fn root_value(bytes: &[u8]) -> Result<&RawValue, FeedError> {
    serde_json::from_slice(bytes).map_err(|error| json_failure(&error))
}


/// `Some` only when the raw value opens with `open` (`[` or `{`).
pub fn opening(raw: &RawValue, open: char) -> Option<&RawValue> {
    raw.get().starts_with(open).then_some(raw)
}


/// One element, at most `MAX_OBJECT_BYTES` of text, parsed alone.
pub fn value_of(text: &str) -> Result<Value, EntryError> {
    if text.len() > MAX_OBJECT_BYTES {
        Err(EntryError::ObjectTooLarge)
    } else {
        serde_json::from_str(text).map_err(|_not_json| EntryError::NotAnObject)
    }
}


/// Items are numbered from 1 in the skip reports and handed to `handler` with their TLP floor; each is parsed alone and dropped after its handler.
pub fn parse_raw_items(feed: &FeedConfig, items: &[Tagged], handler: &ItemHandler) -> Result<Collector, FeedError> {
    items
        .iter()
        .zip(1..)
        .try_fold(new_collector(feed), |mut collector, ((item, level), number)| {
            let outcome = value_of(item.get()).and_then(|value| handler(&value, *level));
            record_bounded(&mut collector, number, outcome).map(|()| collector)
        })
}


/// The items with no TLP floor of their own.
pub fn untagged<'a>(items: &[&'a RawValue]) -> Vec<Tagged<'a>> {
    items.iter().map(|item| (*item, NO_TLP)).collect()
}


/// A document that yielded no IOC and no skip says so: never a silent empty round.
pub fn flag_empty(mut collector: Collector) -> Collector {
    let summary = &collector.summary;
    if collector.iocs.is_empty() && summary.skipped.is_empty() && summary.unsupported == 0 {
        collector.summary.warning = Some(EMPTY_DOCUMENT);
    }
    collector
}


pub fn json_entry(mapping: &Mapping, object: &Map<String, Value>) -> Result<RawEntry, EntryError> {
    raw_entry(mapping, &|name| name.and_then(|field| object.get(field)).and_then(value_text))
}


pub fn json_item(feed: &FeedConfig, now: OffsetDateTime, item: &Value) -> Result<Vec<Ioc>, EntryError> {
    let object = item.as_object().ok_or(EntryError::NotAnObject)?;
    let raw = json_entry(&feed.mapping, object)?;
    Ok(vec![build_ioc(feed, &raw, now)?])
}


/// One IOC per supported comparison of an `indicator`; other object types are not IOCs and are passed over.
pub fn indicator_iocs(feed: &FeedConfig, now: OffsetDateTime, object: &Value) -> Result<Vec<Ioc>, EntryError> {
    if object.get("type").and_then(Value::as_str) == Some(STIX_INDICATOR) {
        let pattern = object.get("pattern").and_then(Value::as_str).ok_or(EntryError::MissingField("pattern"))?;
        let terms = parse_pattern(pattern).ok_or(EntryError::UnsupportedPattern)?;
        let text = |name: &str| object.get(name).and_then(value_text);
        terms
            .iter()
            .map(|term| {
                let raw = RawEntry {
                    value: term.value.clone(),
                    type_name: Some(term.type_name.to_owned()),
                    first_seen: text("valid_from").or_else(|| text("created")),
                    last_seen: text("modified"),
                    confidence: text("confidence"),
                    ..RawEntry::default()
                };
                build_ioc(feed, &raw, now)
            })
            .collect()
    } else {
        Ok(Vec::new())
    }
}


pub fn parse_json_list(feed: &FeedConfig, reader: &mut dyn BufRead, now: OffsetDateTime) -> Result<Collector, FeedError> {
    let bytes = read_document(reader)?;
    let root = opening(root_value(&bytes)?, '[').ok_or(FeedError::NotAnArray)?;
    let items = raw_elements(root, MAX_DOCUMENT_ITEMS).map_err(|error| list_error(error, FeedError::TooManyObjects))?;
    parse_raw_items(feed, &untagged(&items), &|item, _level| json_item(feed, now, item)).map(flag_empty)
}


#[derive(Deserialize)]
pub struct Bundle<'a> {
    #[serde(default, borrow)]
    pub objects: Option<&'a RawValue>,
}


pub fn parse_stix(feed: &FeedConfig, reader: &mut dyn BufRead, now: OffsetDateTime) -> Result<Collector, FeedError> {
    let bytes = read_document(reader)?;
    let root = opening(root_value(&bytes)?, '{').ok_or(FeedError::NotABundle)?;
    let bundle: Bundle = serde_json::from_str(root.get()).map_err(|error| json_failure(&error))?;
    let objects = bundle.objects.and_then(|list| opening(list, '[')).ok_or(FeedError::NotABundle)?;
    let items = raw_elements(objects, MAX_STIX_OBJECTS).map_err(|error| list_error(error, FeedError::TooManyObjects))?;
    parse_raw_items(feed, &untagged(&items), &|object, _level| indicator_iocs(feed, now, object)).map(flag_empty)
}


/// Parses one feed from `reader`; nothing here touches the network or the file system.
pub fn parse_feed(feed: &FeedConfig, reader: &mut dyn BufRead, now: OffsetDateTime) -> Result<Collector, FeedError> {
    match feed.format {
        FeedFormat::Crowdsec => parse_crowdsec(feed, reader, now),
        FeedFormat::AbuseChUrlhaus | FeedFormat::AbuseChThreatfox | FeedFormat::AbuseChFeodo | FeedFormat::Csv => parse_csv(feed, reader, now),
        FeedFormat::Json => parse_json_list(feed, reader, now),
        FeedFormat::Stix => parse_stix(feed, reader, now),
        FeedFormat::Misp => parse_misp(feed, reader, now),
        FeedFormat::Taxii21 => Err(FeedError::PollOnly),
    }
}
