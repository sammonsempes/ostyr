#[path = "common/clock.rs"]
mod clock;
#[path = "common/parsing.rs"]
mod parsing;
#[path = "common/support.rs"]
mod support;
#[path = "common/types.rs"]
mod types;


use intel_feeds::config::{FeedConfig, FeedFormat};
use intel_feeds::error::{EntryError, FeedError};
use intel_feeds::formats::{list_error, new_collector, parse_feed, record_bounded, untagged, value_of, EMPTY_DOCUMENT};
use intel_feeds::limits::{
    MAX_DOCUMENT_BYTES, MAX_DOCUMENT_ITEMS, MAX_FEED_IOCS, MAX_MISP_ATTRIBUTES, MAX_MISP_OBJECTS, MAX_MISP_TAGS, MAX_OBJECT_BYTES, MAX_STIX_OBJECTS,
};
use intel_feeds::misp::{raw_tags_tlp, BAD_OBJECT, BAD_TLP, NO_TLP};
use intel_feeds::model::{Collector, Tlp};
use intel_feeds::scan::{raw_elements, scan_byte, scan_start, ScanError};
use parsing::parse_text;
use serde_json::value::RawValue;
use std::error::Error;
use std::io::{self, BufReader, Read};
use support::feed;
use types::TestResult;


const ATTRIBUTE: &str = r#"{"type":"ip-dst","value":"192.0.2.1","to_ids":true}"#;


const SMALL_CAP: usize = 3;


const SPLIT: usize = 40_001;


const FIRST_LIST: usize = 60_000;


const PAD_ROOM: usize = 100;


const BAD_OBJECTS: u64 = 4;


const PER_NET: usize = 250;


const MARKER: &str = "ZZMARKER";


const NESTED_CAP: usize = 2;


fn raw(text: &str) -> Result<Box<RawValue>, serde_json::Error> {
    serde_json::from_str(text)
}


fn json_feed() -> FeedConfig {
    let mut config = feed("list", FeedFormat::Json);
    config.mapping.value = Some("ioc".to_owned());
    config
}


fn refusal(result: Result<Collector, FeedError>) -> Result<FeedError, Box<dyn Error>> {
    Ok(result.err().ok_or("the document was accepted")?)
}


fn repeated(item: &str, count: usize) -> String {
    vec![item; count].join(",")
}


fn event(inner: &str) -> String {
    format!(r#"{{"Event":{{{inner}}}}}"#)
}


fn parse_misp_text(text: &str) -> Result<Collector, FeedError> {
    parse_text(&feed("misp", FeedFormat::Misp), text)
}


fn skipped(collector: &Collector, reason: &str) -> u64 {
    collector.summary.skipped.get(reason).copied().unwrap_or(0)
}


#[test]
fn the_scan_counts_one_level_and_refuses_the_element_past_the_cap() -> TestResult {
    assert_eq!(raw_elements(&raw("[1,2,3]")?, SMALL_CAP)?.len(), SMALL_CAP);
    assert!(matches!(raw_elements(&raw("[1,2,3,4]")?, SMALL_CAP), Err(ScanError::TooMany)));
    assert_eq!(raw_elements(&raw("[[1,2,3,4,5],{\"a\":1,\"b\":2}]")?, NESTED_CAP)?.len(), NESTED_CAP);
    assert_eq!(raw_elements(&raw(r#"["a,b","c\",d","e\\"]"#)?, SMALL_CAP)?.len(), SMALL_CAP);
    assert!(raw_elements(&raw("[]")?, 0)?.is_empty());
    assert!(matches!(raw_elements(&raw("[1]")?, 0), Err(ScanError::TooMany)));
    assert!(matches!(raw_elements(&raw("{\"a\":1}")?, SMALL_CAP), Err(ScanError::Json { .. })));
    assert!(matches!(raw_elements(&raw("\"text\"")?, SMALL_CAP), Err(ScanError::Json { .. })));
    Ok(())
}


#[test]
fn a_json_list_over_the_item_cap_is_a_named_failed_feed_before_any_item_is_read() -> TestResult {
    let text = format!("[{}]", repeated("0", MAX_DOCUMENT_ITEMS + 1));
    let error = refusal(parse_text(&json_feed(), &text))?;
    assert!(matches!(error, FeedError::TooManyObjects));
    assert!(error.to_string().starts_with("too_many_objects"));
    let nested = format!("[{}]", repeated("[0,0,0]", SMALL_CAP));
    assert_eq!(
        parse_text(&json_feed(), &nested)?.summary.skipped.get("not_an_object"),
        Some(&(SMALL_CAP as u64))
    );
    Ok(())
}


#[test]
fn a_stix_bundle_over_the_object_cap_is_a_named_failed_feed() -> TestResult {
    let flood = format!(r#"{{"objects":[{}]}}"#, repeated("{}", MAX_STIX_OBJECTS + 1));
    let error = refusal(parse_text(&feed("stix", FeedFormat::Stix), &flood))?;
    assert!(matches!(error, FeedError::TooManyObjects));
    let tiny = format!(r#"{{"objects":[{}]}}"#, repeated("0", MAX_STIX_OBJECTS + 1));
    assert!(matches!(
        refusal(parse_text(&feed("stix", FeedFormat::Stix), &tiny))?,
        FeedError::TooManyObjects
    ));
    Ok(())
}


#[test]
fn the_shapes_of_a_bundle_and_a_list_are_checked_before_any_element() -> TestResult {
    let stix = feed("stix", FeedFormat::Stix);
    [
        "[]",
        r#"{"other":1}"#,
        r#"{"objects":"x"}"#,
        r#"{"objects":null}"#,
        r#"[[{"type":"indicator"}]]"#,
    ]
    .iter()
    .try_for_each(|text| -> TestResult {
        assert!(matches!(refusal(parse_text(&stix, text))?, FeedError::NotABundle), "{text}");
        Ok(())
    })?;
    assert!(matches!(refusal(parse_text(&json_feed(), "{}"))?, FeedError::NotAnArray));
    assert!(matches!(refusal(parse_text(&json_feed(), "[1, 2"))?, FeedError::Json { .. }));
    assert!(matches!(
        refusal(parse_text(&stix, r#"{"objects":[],"objects":[]}"#))?,
        FeedError::Json { .. }
    ));
    Ok(())
}


#[test]
fn a_document_that_yields_nothing_is_a_named_warning_never_a_silent_round() -> TestResult {
    let stix = feed("stix", FeedFormat::Stix);
    assert_eq!(parse_text(&json_feed(), "[]")?.summary.warning, Some(EMPTY_DOCUMENT));
    assert_eq!(
        parse_text(&stix, r#"{"objects":[{"type":"identity"}]}"#)?.summary.warning,
        Some(EMPTY_DOCUMENT)
    );
    assert_eq!(parse_misp_text(&event(""))?.summary.warning, Some(EMPTY_DOCUMENT));
    let skipped_only = parse_text(&json_feed(), "[5]")?;
    assert_eq!(skipped_only.summary.warning, None);
    let parsed = parse_text(&json_feed(), r#"[{"ioc":"192.0.2.1"}]"#)?;
    assert_eq!((parsed.iocs.len(), parsed.summary.warning), (1, None));
    let unsupported = parse_text(&stix, r#"{"objects":[{"type":"indicator","pattern":"[a:b = 'c' AND d:e = 'f']"}]}"#)?;
    assert_eq!((unsupported.summary.unsupported, unsupported.summary.warning), (1, None));
    Ok(())
}


#[test]
fn a_misp_object_flood_is_a_named_failed_feed() -> TestResult {
    let flood = event(&format!(r#""Object":[{}]"#, repeated("{}", MAX_MISP_OBJECTS + 1)));
    let error = refusal(parse_misp_text(&flood))?;
    assert!(matches!(error, FeedError::TooManyObjects));
    let tiny = event(&format!(r#""Object":[{}]"#, repeated("0", MAX_MISP_OBJECTS + 1)));
    assert!(matches!(refusal(parse_misp_text(&tiny))?, FeedError::TooManyObjects));
    Ok(())
}


#[test]
fn the_attribute_total_runs_over_the_event_and_every_object() -> TestResult {
    let direct = repeated("0", FIRST_LIST);
    let object = format!(r#"{{"Attribute":[{}]}}"#, repeated("0", SPLIT));
    let text = event(&format!(r#""Attribute":[{direct}],"Object":[{object}]"#));
    let error = refusal(parse_misp_text(&text))?;
    assert!(matches!(error, FeedError::TooManyAttributes));
    assert!(error.to_string().starts_with("too_many_attributes"));
    let slice = MAX_MISP_ATTRIBUTES / SMALL_CAP + 1;
    let each = format!(r#"{{"Attribute":[{}]}}"#, repeated("0", slice));
    let spread = event(&format!(r#""Object":[{}]"#, repeated(&each, SMALL_CAP)));
    assert!(matches!(refusal(parse_misp_text(&spread))?, FeedError::TooManyAttributes));
    let full = event(&format!(
        r#""Object":[{{"Attribute":[{}]}},{{"Attribute":[0]}}]"#,
        repeated("0", MAX_MISP_ATTRIBUTES)
    ));
    assert!(matches!(refusal(parse_misp_text(&full))?, FeedError::TooManyAttributes));
    let direct_flood = event(&format!(r#""Attribute":[{}]"#, repeated("0", MAX_MISP_ATTRIBUTES + 1)));
    assert!(matches!(refusal(parse_misp_text(&direct_flood))?, FeedError::TooManyAttributes));
    Ok(())
}


#[test]
fn an_unreadable_object_is_one_counted_skip_and_the_rest_load() -> TestResult {
    let pad = "a".repeat(MAX_OBJECT_BYTES + PAD_ROOM);
    let objects = [
        "5".to_owned(),
        "[1]".to_owned(),
        r#"{"Attribute":"x"}"#.to_owned(),
        format!(r#"{{"pad":"{pad}","Attribute":[{ATTRIBUTE}]}}"#),
        format!(r#"{{"Attribute":[{ATTRIBUTE}]}}"#),
        r#"{"name":"no attributes"}"#.to_owned(),
        r#"{"Attribute":null}"#.to_owned(),
    ];
    let collector = parse_misp_text(&event(&format!(r#""Object":[{}]"#, objects.join(","))))?;
    assert_eq!(skipped(&collector, BAD_OBJECT), BAD_OBJECTS);
    assert_eq!(collector.iocs.len(), 1);
    assert_eq!(collector.summary.warning, None);
    let only_bad = parse_misp_text(&event(r#""Object":[5]"#))?;
    assert_eq!((skipped(&only_bad, BAD_OBJECT), only_bad.summary.warning), (1, None));
    Ok(())
}


#[test]
fn an_object_that_is_not_a_list_or_an_event_that_is_not_an_object_is_refused() -> TestResult {
    [
        "[]",
        "{}",
        r#"{"Event": 5}"#,
        r#"{"Event": []}"#,
        &event(r#""Attribute":{}"#),
        &event(r#""Object":"x""#),
    ]
    .iter()
    .try_for_each(|text| -> TestResult {
        assert!(matches!(refusal(parse_misp_text(text))?, FeedError::NotAnEvent), "{text}");
        Ok(())
    })?;
    assert!(matches!(refusal(parse_misp_text(r#"{"Event":{},"Event":{}}"#))?, FeedError::Json { .. }));
    assert!(matches!(
        refusal(parse_misp_text(&event(r#""Attribute":[],"Attribute":[]"#)))?,
        FeedError::Json { .. }
    ));
    Ok(())
}


#[test]
fn object_tags_raise_the_tlp_of_their_attributes_and_a_flood_of_tags_reads_red() -> TestResult {
    let red = r#""Tag":[{"name":"tlp:red"}]"#;
    let object_red = parse_misp_text(&event(&format!(r#""Object":[{{{red},"Attribute":[{ATTRIBUTE}]}}]"#)))?;
    assert_eq!(object_red.iocs.first().map(|ioc| ioc.tlp), Some(Tlp::Red));
    assert_eq!(object_red.summary.unknown_tlp, 0);
    let tags = repeated(r#"{"name":"x"}"#, MAX_MISP_TAGS + 1);
    let flooded = parse_misp_text(&event(&format!(r#""Tag":[{tags}],"Attribute":[{ATTRIBUTE}]"#)))?;
    assert_eq!(
        (flooded.iocs.first().map(|ioc| ioc.tlp), flooded.summary.unknown_tlp),
        (Some(Tlp::Red), 1)
    );
    let on_object = parse_misp_text(&event(&format!(r#""Object":[{{"Tag":[{tags}],"Attribute":[{ATTRIBUTE}]}}]"#)))?;
    assert_eq!(
        (on_object.iocs.first().map(|ioc| ioc.tlp), on_object.summary.unknown_tlp),
        (Some(Tlp::Red), 1)
    );
    let within = repeated(r#"{"name":"x"}"#, MAX_MISP_TAGS);
    let allowed = parse_misp_text(&event(&format!(r#""Tag":[{within}],"Attribute":[{ATTRIBUTE}]"#)))?;
    assert_eq!(
        (allowed.iocs.first().map(|ioc| ioc.tlp), allowed.summary.unknown_tlp),
        (Some(Tlp::Amber), 0)
    );
    let on_attribute = format!(r#"{{"type":"ip-dst","value":"192.0.2.1","to_ids":true,"Tag":[{tags}]}}"#);
    let attribute_flood = parse_misp_text(&event(&format!(r#""Attribute":[{on_attribute}]"#)))?;
    assert_eq!(
        (attribute_flood.iocs.first().map(|ioc| ioc.tlp), attribute_flood.summary.unknown_tlp),
        (Some(Tlp::Red), 1)
    );
    let scalar = parse_misp_text(&event(&format!(r#""Tag":"x","Attribute":[{ATTRIBUTE}]"#)))?;
    assert_eq!(scalar.summary.unknown_tlp, 1);
    Ok(())
}


#[test]
fn the_raw_tag_reading_is_fail_closed_per_tag_and_per_list() -> TestResult {
    assert_eq!(raw_tags_tlp(None), NO_TLP);
    assert_eq!(raw_tags_tlp(Some(&raw(r#"[{"name":"tlp:green"},5,{"other":1}]"#)?)).tlp, Tlp::Green);
    assert_eq!(raw_tags_tlp(Some(&raw(r#"[{"name":"tlp:amber"},{"name":"tlp:red"}]"#)?)).tlp, Tlp::Red);
    assert_eq!(raw_tags_tlp(Some(&raw(r#"{"name":"tlp:clear"}"#)?)), BAD_TLP);
    let pad = "a".repeat(MAX_OBJECT_BYTES);
    assert_eq!(raw_tags_tlp(Some(&raw(&format!(r#"[{{"name":"tlp:clear","pad":"{pad}"}}]"#))?)), BAD_TLP);
    Ok(())
}


#[test]
fn a_json_error_keeps_only_category_line_and_column() -> TestResult {
    let text = format!(r#"{{"Event":{{"Attribute":[{{"{MARKER}":1}}]}},"{MARKER}":"{MARKER}","{MARKER}":2 x}}"#);
    let error = refusal(parse_misp_text(&text))?;
    assert!(matches!(error, FeedError::Json { .. }));
    let duplicated = refusal(parse_misp_text(&format!(r#"{{"Event":{{}},"Event":{{"{MARKER}":1}}}}"#)))?;
    [&error, &duplicated].iter().for_each(|failure| {
        assert!(!failure.to_string().contains(MARKER));
        assert!(!format!("{failure:?}").contains(MARKER));
        assert!(std::error::Error::source(*failure).is_none());
    });
    let bundle = refusal(parse_text(
        &feed("stix", FeedFormat::Stix),
        &format!(r#"{{"objects":[],"{MARKER}":1,"objects":[]}}"#),
    ))?;
    assert!(!bundle.to_string().contains(MARKER) && !format!("{bundle:?}").contains(MARKER));
    Ok(())
}


#[test]
fn an_element_over_the_object_cap_is_parsed_never_and_untagged_items_carry_no_floor() -> TestResult {
    let text = format!("\"{}\"", "a".repeat(MAX_OBJECT_BYTES));
    assert!(matches!(value_of(&text), Err(EntryError::ObjectTooLarge)));
    assert!(matches!(value_of("{"), Err(EntryError::NotAnObject)));
    assert_eq!(value_of("[1]")?.as_array().map(Vec::len), Some(1));
    let items = [raw("1")?, raw("2")?];
    let borrowed: Vec<&RawValue> = items.iter().map(AsRef::as_ref).collect();
    assert_eq!(untagged(&borrowed).iter().filter(|(_, level)| *level == NO_TLP).count(), items.len());
    Ok(())
}


#[test]
fn the_count_is_checked_before_the_iocs_are_kept() -> TestResult {
    let config = feed("crowdsec", FeedFormat::Crowdsec);
    let mut collector = new_collector(&config);
    let outcome = |count: usize| {
        let at = parse_text(&feed("crowdsec", FeedFormat::Crowdsec), "192.0.2.1\n").map(|parsed| parsed.iocs);
        at.map(|iocs| iocs.into_iter().cycle().take(count).collect::<Vec<_>>())
    };
    collector.iocs = outcome(MAX_FEED_IOCS)?;
    collector.summary.parsed = MAX_FEED_IOCS as u64;
    let refused = record_bounded(&mut collector, 1, Ok(outcome(1)?));
    assert!(matches!(refused, Err(FeedError::TooManyIocs)));
    assert_eq!(collector.iocs.len(), MAX_FEED_IOCS);
    assert_eq!(collector.summary.parsed, MAX_FEED_IOCS as u64);
    Ok(())
}


#[test]
fn a_scan_error_maps_to_its_feed_error() -> TestResult {
    let scan = raw_elements(&raw("{\"a\":1}")?, SMALL_CAP).err().ok_or("accepted")?;
    assert!(matches!(list_error(scan, FeedError::NotAnArray), FeedError::Json { .. }));
    assert!(matches!(list_error(ScanError::TooMany, FeedError::NotAnArray), FeedError::NotAnArray));
    Ok(())
}


#[test]
fn the_byte_scan_itself_refuses_before_any_element_is_built() -> TestResult {
    let scan = |text: &str, cap: usize| text.bytes().try_fold(scan_start(cap), scan_byte).map(|_| ());
    assert!(matches!(scan("[1,2,3,4]", SMALL_CAP), Err(ScanError::TooMany)));
    assert!(scan("[1,2,3]", SMALL_CAP).is_ok());
    assert!(scan("[[1,2,3,4,5],{\"a\":1,\"b\":2}]", NESTED_CAP).is_ok());
    assert!(matches!(scan("[[1],[2],[3]]", NESTED_CAP), Err(ScanError::TooMany)));
    assert!(matches!(scan("[{},{},{}]", NESTED_CAP), Err(ScanError::TooMany)));
    assert!(scan(r#"["a,b,c,d","\",,,"]"#, NESTED_CAP).is_ok());
    Ok(())
}


const PAIRS: usize = 50_001;


struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("cut"))
    }
}


#[test]
fn a_misp_document_that_cannot_be_read_or_is_too_large_or_yields_too_many_iocs_is_a_named_failed_feed() -> TestResult {
    let config = feed("misp", FeedFormat::Misp);
    let unreadable = parse_feed(&config, &mut BufReader::new(Failing), clock::now());
    assert!(matches!(unreadable, Err(FeedError::Io(_))));
    let big = "a".repeat(MAX_DOCUMENT_BYTES + 1);
    assert!(matches!(refusal(parse_misp_text(&big))?, FeedError::DocumentTooLarge));
    let pair = |number: usize| {
        format!(
            r#"{{"type":"domain|ip","value":"d{number}.example|10.0.{}.{}","to_ids":true}}"#,
            number / PER_NET + 1,
            number % PER_NET + 1
        )
    };
    let attributes = (0..PAIRS).map(pair).collect::<Vec<_>>().join(",");
    let doubled = event(&format!(r#""Attribute":[{attributes}]"#));
    assert!(matches!(refusal(parse_misp_text(&doubled))?, FeedError::TooManyIocs));
    let typeless = parse_misp_text(&event(r#""Attribute":[{"value":"192.0.2.1","to_ids":true}]"#))?;
    assert_eq!(skipped(&typeless, "missing_field"), 1);
    Ok(())
}
