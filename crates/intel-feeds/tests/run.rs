#[path = "common/clock.rs"]
mod clock;
#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/memory.rs"]
mod memory;
#[path = "common/support.rs"]
mod support;
#[path = "common/types.rs"]
mod types;


use clock::now;
use core_config::load::load_file;
use fixtures::fixture;
use intel_feeds::cli::write_summaries;
use intel_feeds::config::{FeedFormat, FeedsFile};
use intel_feeds::dedup::{absorb, insert_ioc};
use intel_feeds::model::{Ioc, IocType, Source, Tags, Tlp};
use intel_feeds::run::{open_file, run_feeds, write_iocs};
use intel_feeds::timestamp::parse_timestamp;
use intel_feeds::types::IocIndex;
use memory::{open_from, FailingWriter};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs;
use support::feed;
use time::OffsetDateTime;
use types::TestResult;


const TWO: u64 = 2;


const THREE: u64 = 3;


const LOW: u8 = 40;


const HIGH: u8 = 90;


const SHORT_TTL: u32 = 60;


fn run_text(config: &FeedsFile, files: &BTreeMap<&str, &str>) -> Result<(Vec<Value>, Vec<Value>), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let summaries = run_feeds(config, now(), &|path| open_from(files, path), &mut out)?;
    let mut report = Vec::new();
    write_summaries(&summaries, &mut report)?;
    let parse =
        |bytes: &[u8]| -> Result<Vec<Value>, serde_json::Error> { String::from_utf8_lossy(bytes).lines().map(serde_json::from_str).collect() };
    Ok((parse(&out)?, parse(&report)?))
}


fn ioc(feed_name: &str, confidence: u8, tlp: Tlp, last_seen: OffsetDateTime, expires_at: Option<OffsetDateTime>, tag: &str) -> Ioc {
    Ioc {
        ioc_type: IocType::Ipv4,
        value: "192.0.2.1".to_owned(),
        sources: vec![Source {
            feed: feed_name.to_owned(),
            version: "1".to_owned(),
        }],
        first_seen: last_seen,
        last_seen,
        confidence,
        tlp,
        expires_at,
        tags: Tags {
            malware: vec![tag.to_owned()],
            actor: Vec::new(),
            campaign: Vec::new(),
        },
    }
}


#[test]
fn one_ioc_per_value_keeps_every_source_and_the_best_attributes() -> TestResult {
    let mut first = feed("first", FeedFormat::Crowdsec);
    first.default_confidence = LOW;
    first.tlp = Tlp::Green;
    first.ttl_seconds = Some(SHORT_TTL * SHORT_TTL);
    let mut second = feed("second", FeedFormat::Crowdsec);
    second.default_confidence = HIGH;
    second.tlp = Tlp::Amber;
    let config = FeedsFile {
        feeds: vec![first, second],
        ..FeedsFile::default()
    };
    let files = BTreeMap::from([("first", "192.0.2.1\n192.0.2.1\n"), ("second", "192.0.2.1\n")]);
    let (iocs, summaries) = run_text(&config, &files)?;
    assert_eq!(iocs.len(), 1);
    let merged = iocs.first().ok_or("no ioc")?;
    assert_eq!(merged["confidence"], HIGH);
    assert_eq!(merged["tlp"], "amber");
    assert_eq!(merged["expires_at"], Value::Null);
    assert_eq!(merged["sources"].as_array().map(Vec::len), Some(TWO as usize));
    assert_eq!(summaries.first().map(|summary| summary["duplicates"].clone()), Some(Value::from(1)));
    assert_eq!(summaries.get(1).map(|summary| summary["duplicates"].clone()), Some(Value::from(1)));
    Ok(())
}


#[test]
fn expired_iocs_are_dropped_and_counted_with_an_injected_clock() -> TestResult {
    let mut config = feed("old", FeedFormat::Csv);
    config.mapping.value = Some("indicator".to_owned());
    config.mapping.last_seen = Some("seen".to_owned());
    config.ttl_seconds = Some(SHORT_TTL);
    let text = "indicator,seen\n192.0.2.9,2026-01-01 00:00:00\n192.0.2.10,2026-11-03 11:59:00\n192.0.2.11,2026-11-03 11:59:01\n";
    let files = BTreeMap::from([("old", text)]);
    let (iocs, summaries) = run_text(
        &FeedsFile {
            feeds: vec![config],
            ..FeedsFile::default()
        },
        &files,
    )?;
    assert_eq!(
        iocs.iter().map(|line| line["value"].clone()).collect::<Vec<_>>(),
        vec![Value::from("192.0.2.11")]
    );
    assert_eq!(summaries.first().map(|summary| summary["expired"].clone()), Some(Value::from(TWO)));
    assert_eq!(summaries.first().map(|summary| summary["parsed"].clone()), Some(Value::from(THREE)));
    Ok(())
}


#[test]
fn an_unreadable_feed_is_reported_and_the_others_still_run() -> TestResult {
    let config = FeedsFile {
        feeds: vec![feed("missing", FeedFormat::Crowdsec), feed("present", FeedFormat::Crowdsec)],
        ..FeedsFile::default()
    };
    let files = BTreeMap::from([("present", "192.0.2.1\n")]);
    let (iocs, summaries) = run_text(&config, &files)?;
    assert_eq!(iocs.len(), 1);
    assert!(summaries.first().ok_or("no summary")?["failed"].is_string());
    assert_eq!(summaries.get(1).map(|summary| summary["failed"].clone()), Some(Value::Null));
    Ok(())
}


#[test]
fn a_failing_output_is_an_error() -> TestResult {
    let config = FeedsFile {
        feeds: vec![feed("present", FeedFormat::Crowdsec)],
        ..FeedsFile::default()
    };
    let files = BTreeMap::from([("present", "192.0.2.1\n")]);
    assert!(run_feeds(&config, now(), &|path| open_from(&files, path), &mut FailingWriter).is_err());
    assert!(write_iocs(&IocIndex::new(), &mut FailingWriter).is_ok());
    Ok(())
}


#[test]
fn merging_keeps_the_extremes_and_never_expires_without_a_ttl() -> TestResult {
    let early = parse_timestamp("2026-11-01 00:00:00")?;
    let late = parse_timestamp("2026-11-02 00:00:00")?;
    let later = parse_timestamp("2026-11-03 00:00:00")?;
    let mut index = IocIndex::new();
    assert!(!insert_ioc(&mut index, ioc("a", LOW, Tlp::Red, late, Some(late), "x")));
    assert!(insert_ioc(&mut index, ioc("b", HIGH, Tlp::Clear, early, Some(later), "y")));
    assert!(insert_ioc(&mut index, ioc("a", LOW, Tlp::Clear, late, Some(early), "x")));
    let merged = index.values().next();
    assert_eq!(merged.map(|found| found.first_seen), Some(early));
    assert_eq!(merged.map(|found| found.last_seen), Some(late));
    assert_eq!(merged.map(|found| found.confidence), Some(HIGH));
    assert_eq!(merged.map(|found| found.tlp), Some(Tlp::Red));
    assert_eq!(merged.and_then(|found| found.expires_at), Some(later));
    assert_eq!(merged.map(|found| found.sources.len()), Some(TWO as usize));
    assert_eq!(merged.map(|found| found.tags.malware.clone()), Some(vec!["x".to_owned(), "y".to_owned()]));
    let mut open_ended = ioc("c", LOW, Tlp::Clear, late, None, "z");
    absorb(&mut open_ended, ioc("d", LOW, Tlp::Clear, late, Some(late), "z"));
    assert_eq!(open_ended.expires_at, None);
    Ok(())
}


#[test]
fn fixture_feeds_produce_the_committed_snapshots() -> TestResult {
    let config: FeedsFile = load_file(&fixture("feeds.yaml"))?;
    let mut out = Vec::new();
    let summaries = run_feeds(&config, now(), &|path| open_file(&fixture(&path.to_string_lossy())), &mut out)?;
    let mut report = Vec::new();
    write_summaries(&summaries, &mut report)?;
    assert_eq!(String::from_utf8(out)?, fs::read_to_string(fixture("expected.jsonl"))?);
    assert_eq!(String::from_utf8(report)?, fs::read_to_string(fixture("expected-summary.jsonl"))?);
    assert!(open_file(&fixture("absent.csv")).is_err());
    Ok(())
}
