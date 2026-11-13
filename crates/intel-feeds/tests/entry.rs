#[path = "common/clock.rs"]
mod clock;
#[path = "common/support.rs"]
mod support;
#[path = "common/types.rs"]
mod types;


use clock::now;
use intel_feeds::config::FeedFormat;
use intel_feeds::entry::{build_ioc, confidence_or, split_tags, strip_port, time_or};
use intel_feeds::error::EntryError;
use intel_feeds::limits::{MAX_TAGS_PER_FIELD, MAX_TAG_BYTES};
use intel_feeds::model::{IocType, RawEntry, Tlp};
use intel_feeds::timestamp::parse_timestamp;
use std::error::Error;
use support::feed;
use time::format_description::well_known::Rfc3339;
use types::TestResult;


const EXTRA_TAGS: usize = 4;


const TTL: u32 = 3_600;


const CONFIDENCE_LIMIT: u8 = 100;


const DEFAULT: u8 = 42;


#[test]
fn timestamps_accept_rfc3339_and_the_abusech_layout() -> TestResult {
    let rendered = |text: &str| -> Result<String, Box<dyn Error>> { Ok(parse_timestamp(text)?.format(&Rfc3339)?) };
    assert_eq!(rendered("2026-11-01T00:00:00.000Z")?, "2026-11-01T00:00:00Z");
    assert_eq!(rendered(" 2026-11-01 08:30:00 ")?, "2026-11-01T08:30:00Z");
    assert_eq!(rendered("2026-11-01 08:30:00 UTC")?, "2026-11-01T08:30:00Z");
    assert!(matches!(parse_timestamp("yesterday"), Err(EntryError::Timestamp { .. })));
    Ok(())
}


#[test]
fn a_time_that_leaves_the_range_in_utc_is_refused_not_a_panic() -> TestResult {
    [
        "9999-12-31T23:00:00-02:00",
        "9999-12-31T23:59:59-00:01",
        "0000-01-01T00:00:00+00:01",
        "0000-01-01T00:30:00+01:00",
    ]
    .iter()
    .for_each(|text| assert!(matches!(parse_timestamp(text), Err(EntryError::TimestampRange { .. })), "{text}"));
    assert_eq!(parse_timestamp("2026-11-01T02:00:00+02:00")?, parse_timestamp("2026-11-01T00:00:00Z")?);
    assert_eq!(parse_timestamp("2026-11-01T02:00:00+02:00")?.offset(), time::UtcOffset::UTC);
    let error = parse_timestamp("9999-12-31T23:00:00-02:00").err().ok_or("no error")?;
    assert_eq!(intel_feeds::error::reason_key(&error), "invalid_timestamp");
    Ok(())
}


#[test]
fn absent_times_fall_back_and_bad_ones_are_errors() -> TestResult {
    assert_eq!(time_or(None, now())?, now());
    assert_eq!(time_or(Some("2026-11-01 08:30:00"), now())?, parse_timestamp("2026-11-01 08:30:00")?);
    assert!(time_or(Some("nope"), now()).is_err());
    Ok(())
}


#[test]
fn confidence_is_a_number_from_0_to_100() -> TestResult {
    assert_eq!(confidence_or(None, DEFAULT)?, DEFAULT);
    assert_eq!(confidence_or(Some(" 100 "), DEFAULT)?, CONFIDENCE_LIMIT);
    assert_eq!(confidence_or(Some("0"), DEFAULT)?, 0);
    assert!(matches!(
        confidence_or(Some("many"), DEFAULT),
        Err(EntryError::Confidence { source: Some(_), .. })
    ));
    assert!(matches!(
        confidence_or(Some("101"), DEFAULT),
        Err(EntryError::Confidence { source: None, .. })
    ));
    Ok(())
}


#[test]
fn tags_are_trimmed_bounded_and_filtered() -> TestResult {
    assert_eq!(split_tags(None), Vec::<String>::new());
    assert_eq!(split_tags(Some(" a , ,b,")), vec!["a".to_owned(), "b".to_owned()]);
    let many = vec!["t"; MAX_TAGS_PER_FIELD + EXTRA_TAGS].join(",");
    assert_eq!(split_tags(Some(&many)).len(), MAX_TAGS_PER_FIELD);
    let long = "x".repeat(MAX_TAG_BYTES + 1);
    assert_eq!(split_tags(Some(&long)), Vec::<String>::new());
    Ok(())
}


#[test]
fn ports_are_removed_from_socket_addresses_only() -> TestResult {
    assert_eq!(strip_port("1.2.3.4:443"), "1.2.3.4");
    assert_eq!(strip_port(" [2001:db8::1]:443 "), "2001:db8::1");
    assert_eq!(strip_port("evil.example:80"), "evil.example:80");
    assert_eq!(strip_port("2001:db8::1"), "2001:db8::1");
    Ok(())
}


#[test]
fn an_ioc_carries_its_feed_ttl_and_tlp() -> TestResult {
    let mut config = feed("partner", FeedFormat::Csv);
    config.version = Some("v7".to_owned());
    config.ttl_seconds = Some(TTL);
    config.tlp = Tlp::Red;
    let raw = RawEntry {
        value: "Evil.Example.".to_owned(),
        last_seen: Some("2026-11-01 00:00:00".to_owned()),
        campaign: Some("Op One".to_owned()),
        ..RawEntry::default()
    };
    let ioc = build_ioc(&config, &raw, now())?;
    assert_eq!((ioc.ioc_type, ioc.value.as_str()), (IocType::Domain, "evil.example"));
    assert_eq!(ioc.expires_at, Some(parse_timestamp("2026-11-01 01:00:00")?));
    assert_eq!(ioc.tlp, Tlp::Red);
    assert_eq!(ioc.sources.first().map(|source| source.version.as_str()), Some("v7"));
    assert_eq!(ioc.tags.campaign, vec!["Op One".to_owned()]);
    let plain = build_ioc(&feed("plain", FeedFormat::Csv), &raw, now())?;
    assert_eq!(plain.expires_at, None);
    assert_eq!(plain.sources.first().map(|source| source.version.as_str()), Some("unversioned"));
    Ok(())
}


#[test]
fn a_declared_type_wins_over_detection() -> TestResult {
    let raw = RawEntry {
        value: "10.1.2.3/8".to_owned(),
        type_name: Some("cidr".to_owned()),
        ..RawEntry::default()
    };
    assert_eq!(build_ioc(&feed("x", FeedFormat::Csv), &raw, now())?.value, "10.0.0.0/8");
    Ok(())
}
