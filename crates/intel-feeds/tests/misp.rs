#[path = "common/clock.rs"]
mod clock;
#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/parsing.rs"]
mod parsing;
#[path = "common/support.rs"]
mod support;
#[path = "common/types.rs"]
mod types;


use clock::now;
use fixtures::fixture;
use intel_feeds::config::{FeedConfig, FeedFormat};
use intel_feeds::error::{reason_key, EntryError, FeedError};
use intel_feeds::limits::{MAX_MISP_ATTRIBUTES, MAX_OBJECT_BYTES};
use intel_feeds::misp::{flag, ip_part, known_level, misp_parts, tags_tlp, tlp_of_tag, unix_as_rfc3339, BAD_TLP, NO_TLP};
use intel_feeds::model::{Collector, Ioc, IocType, Tlp};
use parsing::parse_text;
use serde_json::{json, Value};
use std::fs;
use support::feed;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use types::TestResult;


const EXPECTED_PARSED: u64 = 16;


const TIMESTAMP_SECONDS: i64 = 1_762_000_000;


const TWO: u64 = 2;


const THREE: u64 = 3;


const SECONDS_PER_DAY: i64 = 86_400;


fn misp_feed(tlp: Tlp) -> FeedConfig {
    let mut config = feed("misp", FeedFormat::Misp);
    config.tlp = tlp;
    config
}


fn fixture_run(tlp: Tlp) -> Result<Collector, Box<dyn std::error::Error>> {
    Ok(parse_text(&misp_feed(tlp), &fs::read_to_string(fixture("misp.json"))?)?)
}


fn find<'a>(collector: &'a Collector, value: &str) -> Result<&'a Ioc, String> {
    collector
        .iocs
        .iter()
        .find(|ioc| ioc.value == value)
        .ok_or_else(|| format!("no ioc {value}"))
}


fn skipped(collector: &Collector, reason: &str) -> u64 {
    collector.summary.skipped.get(reason).copied().unwrap_or(0)
}


fn event_text(attributes: &Value) -> String {
    json!({"Event": {"Attribute": attributes}}).to_string()
}


#[test]
fn every_mapped_type_is_normalised() -> TestResult {
    let collector = fixture_run(Tlp::Clear)?;
    assert_eq!(collector.summary.parsed, EXPECTED_PARSED);
    assert_eq!(find(&collector, "198.51.100.7")?.ioc_type, IocType::Ipv4);
    assert_eq!(find(&collector, "203.0.113.5")?.ioc_type, IocType::Ipv4);
    assert_eq!(find(&collector, "192.0.2.0/24")?.ioc_type, IocType::Cidr);
    assert_eq!(find(&collector, "2001:db8::1")?.ioc_type, IocType::Ipv6);
    assert_eq!(find(&collector, "evil.example")?.ioc_type, IocType::Domain);
    assert_eq!(find(&collector, "host.example.net")?.ioc_type, IocType::Domain);
    assert_eq!(find(&collector, "dual.example")?.ioc_type, IocType::Domain);
    assert_eq!(find(&collector, "192.0.2.99")?.ioc_type, IocType::Ipv4);
    assert_eq!(find(&collector, "http://bad.example/x")?.ioc_type, IocType::Url);
    assert_eq!(find(&collector, "d41d8cd98f00b204e9800998ecf8427e")?.ioc_type, IocType::Md5);
    assert_eq!(find(&collector, "da39a3ee5e6b4b0d3255bfef95601890afd80709")?.ioc_type, IocType::Sha1);
    assert_eq!(
        find(&collector, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")?.ioc_type,
        IocType::Sha256
    );
    assert_eq!(find(&collector, "192.0.2.77")?.ioc_type, IocType::Ipv4);
    Ok(())
}


#[test]
fn skips_and_bad_values_are_counted_by_reason() -> TestResult {
    let collector = fixture_run(Tlp::Clear)?;
    assert_eq!(skipped(&collector, "not_for_detection"), TWO);
    assert_eq!(skipped(&collector, "deleted"), 1);
    assert_eq!(collector.summary.unsupported, 1);
    assert_eq!(skipped(&collector, "control_character"), 1);
    assert_eq!(skipped(&collector, "invalid_value"), THREE);
    assert_eq!(skipped(&collector, "invalid_timestamp"), 1);
    assert_eq!(skipped(&collector, "missing_field"), 1);
    assert_eq!(skipped(&collector, "not_an_object"), 1);
    [
        "halfbad.example",
        "nope",
        "badtime.example",
        "not-for-detection.example",
        "deleted.example",
        "a@b.example",
    ]
    .iter()
    .for_each(|value| assert!(collector.iocs.iter().all(|ioc| &ioc.value != value), "{value} stored"));
    Ok(())
}


#[test]
fn a_half_bad_composite_is_refused_whole() -> TestResult {
    let collector = parse_text(
        &misp_feed(Tlp::Clear),
        &event_text(&json!([{"type": "domain|ip", "value": "kept.example|nope", "to_ids": true}])),
    )?;
    assert!(collector.iocs.is_empty());
    assert_eq!(skipped(&collector, "invalid_value"), 1);
    Ok(())
}


#[test]
fn tlp_is_the_strictest_of_feed_event_and_attribute() -> TestResult {
    let collector = fixture_run(Tlp::Clear)?;
    assert_eq!(find(&collector, "198.51.100.7")?.tlp, Tlp::Green);
    assert_eq!(find(&collector, "tag-red.example")?.tlp, Tlp::Red);
    assert_eq!(find(&collector, "tag-white.example")?.tlp, Tlp::Green);
    assert_eq!(find(&collector, "odd-tlp.example")?.tlp, Tlp::Red);
    assert_eq!(collector.summary.unknown_tlp, 1);
    let amber = fixture_run(Tlp::Amber)?;
    assert_eq!(find(&amber, "198.51.100.7")?.tlp, Tlp::Amber);
    let red = fixture_run(Tlp::Red)?;
    assert!(red.iocs.iter().all(|ioc| ioc.tlp == Tlp::Red));
    Ok(())
}


#[test]
fn an_attribute_tag_never_downgrades_the_event_tag() -> TestResult {
    let text = json!({"Event": {"Tag": [{"name": "tlp:red"}], "Attribute": [
        {"type": "domain", "value": "a.example", "to_ids": true, "Tag": [{"name": "tlp:clear"}]}]}})
    .to_string();
    let collector = parse_text(&misp_feed(Tlp::Clear), &text)?;
    assert_eq!(find(&collector, "a.example")?.tlp, Tlp::Red);
    Ok(())
}


#[test]
fn an_event_with_an_unknown_tag_makes_every_item_red_and_counted() -> TestResult {
    let text = json!({"Event": {"Tag": [{"name": "tlp:nope"}], "Attribute": [
        {"type": "domain", "value": "a.example", "to_ids": true}]}})
    .to_string();
    let collector = parse_text(&misp_feed(Tlp::Clear), &text)?;
    assert_eq!(find(&collector, "a.example")?.tlp, Tlp::Red);
    assert_eq!(collector.summary.unknown_tlp, 1);
    Ok(())
}


#[test]
fn times_come_from_the_attribute_then_the_timestamp_then_now() -> TestResult {
    let collector = fixture_run(Tlp::Clear)?;
    let dated = find(&collector, "evil.example")?;
    assert_eq!(dated.first_seen, OffsetDateTime::parse("2026-11-01T08:00:00Z", &Rfc3339)?);
    assert_eq!(dated.last_seen.unix_timestamp(), dated.first_seen.unix_timestamp() + SECONDS_PER_DAY);
    let stamped = find(&collector, "host.example.net")?;
    assert_eq!(stamped.first_seen.unix_timestamp(), TIMESTAMP_SECONDS);
    assert_eq!(stamped.last_seen.unix_timestamp(), TIMESTAMP_SECONDS);
    assert_eq!(find(&collector, "198.51.100.7")?.first_seen, now());
    Ok(())
}


#[test]
fn a_bad_timestamp_attribute_is_a_counted_bad_entry() -> TestResult {
    let collector = parse_text(
        &misp_feed(Tlp::Clear),
        &event_text(&json!([{"type": "domain", "value": "a.example", "to_ids": true, "timestamp": "soon"}])),
    )?;
    assert_eq!(skipped(&collector, "invalid_timestamp"), 1);
    assert_eq!(unix_as_rfc3339("soon"), "soon");
    assert_eq!(unix_as_rfc3339(&i64::MAX.to_string()), i64::MAX.to_string());
    Ok(())
}


#[test]
fn a_file_over_the_attribute_cap_is_refused() -> TestResult {
    let attribute = json!({"type": "domain", "value": "a.example", "to_ids": true});
    let direct = vec![attribute.clone(); MAX_MISP_ATTRIBUTES];
    let at_cap = parse_text(&misp_feed(Tlp::Clear), &event_text(&Value::Array(direct.clone())))?;
    assert_eq!(at_cap.summary.parsed, MAX_MISP_ATTRIBUTES as u64);
    let mut over = direct;
    over.push(attribute.clone());
    assert!(matches!(
        parse_text(&misp_feed(Tlp::Clear), &event_text(&Value::Array(over))),
        Err(FeedError::TooManyAttributes)
    ));
    let nested = json!({"Event": {"Attribute": vec![attribute.clone(); MAX_MISP_ATTRIBUTES], "Object": [{"Attribute": [attribute]}]}});
    let refusal = parse_text(&misp_feed(Tlp::Clear), &nested.to_string())
        .err()
        .map(|error| error.to_string());
    assert!(refusal.ok_or("accepted")?.contains(&MAX_MISP_ATTRIBUTES.to_string()));
    Ok(())
}


#[test]
fn a_document_that_is_not_an_event_is_refused() -> TestResult {
    let config = misp_feed(Tlp::Clear);
    [
        "[]",
        "{}",
        r#"{"Event": []}"#,
        r#"{"Event": {"Attribute": {}}}"#,
        r#"{"Event": {"Object": "x"}}"#,
        r#"{"Event": {"Object": [{"Attribute": 3}]}}"#,
    ]
    .iter()
    .for_each(|text| assert!(matches!(parse_text(&config, text), Err(FeedError::NotAnEvent)), "{text}"));
    assert!(matches!(parse_text(&config, "{"), Err(FeedError::Json(_))));
    Ok(())
}


#[test]
fn an_empty_event_has_no_items() -> TestResult {
    let collector = parse_text(&misp_feed(Tlp::Clear), r#"{"Event": {"Attribute": null, "Tag": null}}"#)?;
    assert_eq!(collector.summary.parsed, 0);
    Ok(())
}


#[test]
fn an_attribute_over_the_object_cap_is_skipped() -> TestResult {
    let big = "a".repeat(MAX_OBJECT_BYTES);
    let collector = parse_text(
        &misp_feed(Tlp::Clear),
        &event_text(&json!([{"type": "domain", "value": "a.example", "to_ids": true, "comment": big}])),
    )?;
    assert_eq!(skipped(&collector, "object_too_large"), 1);
    assert!(collector.iocs.is_empty());
    Ok(())
}


#[test]
fn plain_sha1_and_filename_md5_attributes_map_to_their_hash() -> TestResult {
    let attributes = json!([
        {"type": "sha1", "value": "da39a3ee5e6b4b0d3255bfef95601890afd80709", "to_ids": true},
        {"type": "filename|md5", "value": "x.exe|d41d8cd98f00b204e9800998ecf8427e", "to_ids": true}
    ]);
    let collector = parse_text(&misp_feed(Tlp::Clear), &event_text(&attributes))?;
    assert_eq!(find(&collector, "da39a3ee5e6b4b0d3255bfef95601890afd80709")?.ioc_type, IocType::Sha1);
    assert_eq!(find(&collector, "d41d8cd98f00b204e9800998ecf8427e")?.ioc_type, IocType::Md5);
    Ok(())
}


#[test]
fn the_table_and_helpers_behave() -> TestResult {
    assert!(misp_parts("comment", "x").is_none());
    assert_eq!(misp_parts("ip-dst|port", "1.2.3.4").ok_or("none")?.len(), 1);
    assert_eq!(misp_parts("domain|ip", "only.example").ok_or("none")?.len(), TWO as usize);
    assert_eq!(ip_part("10.0.0.0/8").type_name, "cidr");
    assert_eq!(tlp_of_tag(" TLP:Amber+Strict "), Some(known_level(Tlp::AmberStrict)));
    assert_eq!(tlp_of_tag("tlp:amber"), Some(known_level(Tlp::Amber)));
    assert_eq!(tlp_of_tag("other"), None);
    assert_eq!(tags_tlp(None), NO_TLP);
    assert_eq!(tags_tlp(Some(&json!("tlp:red"))), BAD_TLP);
    assert_eq!(tags_tlp(Some(&Value::Null)), NO_TLP);
    let object: Value = serde_json::from_str(r#"{"a": "TRUE", "b": "0", "c": 1, "d": 2, "e": null}"#)?;
    let map = object.as_object().ok_or("object")?;
    assert!(flag(map, "a") && flag(map, "c"));
    assert!(!flag(map, "b") && !flag(map, "d") && !flag(map, "e") && !flag(map, "missing"));
    assert_eq!(reason_key(&EntryError::NotForDetection), "not_for_detection");
    assert_eq!(reason_key(&EntryError::Deleted), "deleted");
    assert_eq!(reason_key(&EntryError::ControlCharacter), "control_character");
    Ok(())
}
