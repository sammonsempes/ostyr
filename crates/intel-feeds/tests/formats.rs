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
use intel_feeds::config::{FeedFormat, Mapping};
use intel_feeds::error::{reason_key, EntryError, FeedError};
use intel_feeds::formats::{abusech_layout, csv_record, parse_feed};
use intel_feeds::limits::{MAX_DOCUMENT_BYTES, MAX_LINE_BYTES, MAX_OBJECT_BYTES, MAX_REPORTED_SKIPS};
use intel_feeds::model::{Collector, IocType};
use intel_feeds::timestamp::parse_timestamp;
use parsing::parse_text;
use std::fs;
use std::io::{self, BufReader, Read};
use support::feed;
use types::TestResult;


const URLHAUS_BAD_LINE: u64 = 7;


const CROWDSEC_PARSED: u64 = 6;


const CROWDSEC_SKIPPED: u64 = 2;


const CROWDSEC_BAD_LINES: [u64; 2] = [8, 9];


const JSON_BAD_LINES: [u64; 2] = [3, 4];


const PARTNER_CONFIDENCE: u8 = 80;


const STIX_CONFIDENCE: u8 = 85;


const EXTRA_SKIPS: usize = 5;


const JSON_NOT_TEXT: u64 = 4;


const EXPECTED_URLHAUS_IOCS: usize = 2;


const THREATFOX_CONFIDENCE: u8 = 75;


const EXPECTED_STIX_PARSED: u64 = 4;


struct Broken;


impl Read for Broken {
    fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
        Err(io::Error::other("injected"))
    }
}


fn collect_fixture(name: &str, format: FeedFormat, mapping: Mapping) -> Result<Collector, Box<dyn std::error::Error>> {
    let mut config = feed(name, format);
    config.mapping = mapping;
    let mut reader = BufReader::new(fs::File::open(fixture(name))?);
    Ok(parse_feed(&config, &mut reader, now())?)
}


fn values_of(collector: &Collector) -> Vec<String> {
    collector.iocs.iter().map(|ioc| ioc.value.clone()).collect()
}


fn skipped(collector: &Collector, reason: &str) -> u64 {
    collector.summary.skipped.get(reason).copied().unwrap_or(0)
}


#[test]
fn urlhaus_export_is_normalised() -> TestResult {
    let collector = collect_fixture("urlhaus.csv", FeedFormat::AbuseChUrlhaus, Mapping::default())?;
    assert_eq!(collector.iocs.len(), EXPECTED_URLHAUS_IOCS);
    assert_eq!(
        values_of(&collector),
        vec![
            "http://evil.example.com/payload.sh".to_owned(),
            "http://203.0.113.9:8080/a.exe".to_owned()
        ]
    );
    let first = collector.iocs.first().ok_or("no ioc")?;
    assert_eq!(first.ioc_type, IocType::Url);
    assert_eq!(first.first_seen, parse_timestamp("2026-11-01 08:00:00")?);
    assert_eq!(first.last_seen, now());
    assert_eq!(first.tags.malware, vec!["elf".to_owned(), "Mozi".to_owned()]);
    assert_eq!(skipped(&collector, "invalid_value"), 1);
    assert_eq!(collector.summary.samples.first().map(|sample| sample.line), Some(URLHAUS_BAD_LINE));
    Ok(())
}


#[test]
fn threatfox_export_strips_ports_and_reports_each_skip_reason() -> TestResult {
    let collector = collect_fixture("threatfox.csv", FeedFormat::AbuseChThreatfox, Mapping::default())?;
    assert_eq!(
        values_of(&collector),
        vec![
            "198.51.100.7".to_owned(),
            "bad.example.org".to_owned(),
            "d41d8cd98f00b204e9800998ecf8427e".to_owned()
        ]
    );
    let first = collector.iocs.first().ok_or("no ioc")?;
    assert_eq!(first.confidence, THREATFOX_CONFIDENCE);
    assert_eq!(first.last_seen, parse_timestamp("2026-11-02 01:00:00")?);
    assert_eq!(first.tags.malware, vec!["Example RAT".to_owned()]);
    assert_eq!(skipped(&collector, "invalid_value"), 1);
    assert_eq!(skipped(&collector, "invalid_confidence"), 1);
    assert_eq!(skipped(&collector, "invalid_timestamp"), 1);
    Ok(())
}


#[test]
fn feodo_export_keeps_ipv4_and_ipv6() -> TestResult {
    let collector = collect_fixture("feodo.csv", FeedFormat::AbuseChFeodo, Mapping::default())?;
    assert_eq!(values_of(&collector), vec!["192.0.2.50".to_owned(), "2001:db8::1".to_owned()]);
    assert_eq!(collector.iocs.get(1).map(|ioc| ioc.ioc_type), Some(IocType::Ipv6));
    Ok(())
}


#[test]
fn crowdsec_blocklist_is_one_address_or_network_per_line() -> TestResult {
    let collector = collect_fixture("crowdsec.txt", FeedFormat::Crowdsec, Mapping::default())?;
    assert_eq!(
        values_of(&collector),
        vec![
            "192.0.2.1".to_owned(),
            "198.51.100.0/24".to_owned(),
            "10.0.0.0/8".to_owned(),
            "192.0.2.77".to_owned(),
            "2001:db8::5".to_owned(),
            "192.0.2.50".to_owned()
        ]
    );
    assert_eq!(collector.summary.parsed, CROWDSEC_PARSED);
    assert_eq!(skipped(&collector, "invalid_value"), CROWDSEC_SKIPPED);
    assert_eq!(
        collector.summary.samples.iter().map(|sample| sample.line).collect::<Vec<_>>(),
        CROWDSEC_BAD_LINES
    );
    Ok(())
}


#[test]
fn generic_csv_follows_the_declared_mapping() -> TestResult {
    let mapping = Mapping {
        value: Some("indicator".to_owned()),
        ioc_type: Some("kind".to_owned()),
        first_seen: Some("seen".to_owned()),
        confidence: Some("score".to_owned()),
        malware: Some("family".to_owned()),
        actor: Some("who".to_owned()),
        ..Mapping::default()
    };
    let collector = collect_fixture("generic.csv", FeedFormat::Csv, mapping)?;
    assert_eq!(values_of(&collector), vec!["evil.example".to_owned(), "192.0.2.200".to_owned()]);
    let first = collector.iocs.first().ok_or("no ioc")?;
    assert_eq!(
        (first.confidence, first.tags.actor.clone()),
        (PARTNER_CONFIDENCE, vec!["APT99".to_owned()])
    );
    assert_eq!(
        collector.iocs.get(1).map(|ioc| ioc.first_seen),
        Some(parse_timestamp("2026-11-01 05:00:00")?)
    );
    assert_eq!(skipped(&collector, "missing_field"), 1);
    Ok(())
}


#[test]
fn json_list_follows_the_declared_mapping() -> TestResult {
    let mapping = Mapping {
        value: Some("ioc".to_owned()),
        ioc_type: Some("type".to_owned()),
        confidence: Some("score".to_owned()),
        malware: Some("tags".to_owned()),
        ..Mapping::default()
    };
    let collector = collect_fixture("list.json", FeedFormat::Json, mapping)?;
    assert_eq!(values_of(&collector), vec!["evil2.example".to_owned(), "192.0.2.201".to_owned()]);
    assert_eq!(
        collector.iocs.first().map(|ioc| ioc.tags.malware.clone()),
        Some(vec!["a".to_owned(), "b".to_owned()])
    );
    assert_eq!(skipped(&collector, "not_an_object"), 1);
    assert_eq!(skipped(&collector, "missing_field"), 1);
    assert_eq!(
        collector.summary.samples.iter().map(|sample| sample.line).collect::<Vec<_>>(),
        JSON_BAD_LINES
    );
    Ok(())
}


#[test]
fn stix_bundle_yields_supported_patterns_and_counts_the_rest() -> TestResult {
    let collector = collect_fixture("bundle.json", FeedFormat::Stix, Mapping::default())?;
    assert_eq!(
        values_of(&collector),
        vec![
            "192.0.2.10".to_owned(),
            "stix.example".to_owned(),
            "http://stix.example/x".to_owned(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_owned()
        ]
    );
    assert_eq!(collector.summary.parsed, EXPECTED_STIX_PARSED);
    assert_eq!(collector.summary.unsupported, 1);
    assert_eq!(skipped(&collector, "missing_field"), 1);
    assert_eq!(skipped(&collector, "invalid_value"), 1);
    let first = collector.iocs.first().ok_or("no ioc")?;
    assert_eq!(first.first_seen, parse_timestamp("2026-10-02 00:00:00")?);
    assert_eq!(first.last_seen, parse_timestamp("2026-11-01 00:00:00")?);
    assert_eq!(first.confidence, STIX_CONFIDENCE);
    assert_eq!(
        collector.iocs.get(1).map(|ioc| ioc.first_seen),
        Some(parse_timestamp("2026-10-03 00:00:00")?)
    );
    Ok(())
}


#[test]
fn only_the_abusech_formats_have_a_fixed_layout() -> TestResult {
    assert!(abusech_layout(FeedFormat::AbuseChUrlhaus).is_some());
    assert!(abusech_layout(FeedFormat::AbuseChThreatfox).is_some());
    assert!(abusech_layout(FeedFormat::AbuseChFeodo).is_some());
    assert!(abusech_layout(FeedFormat::Csv).is_none());
    assert!(abusech_layout(FeedFormat::Stix).is_none());
    Ok(())
}


#[test]
fn a_line_over_the_cap_is_skipped_and_the_next_one_parsed() -> TestResult {
    let text = format!("{}\n192.0.2.1\n", "9".repeat(MAX_LINE_BYTES + 1));
    let collector = parse_text(&feed("crowdsec", FeedFormat::Crowdsec), &text)?;
    assert_eq!(values_of(&collector), vec!["192.0.2.1".to_owned()]);
    assert_eq!(skipped(&collector, "line_too_long"), 1);
    Ok(())
}


#[test]
fn invalid_utf8_lines_are_skipped() -> TestResult {
    let mut reader = BufReader::new(&b"\xff\xfe\n192.0.2.1\n"[..]);
    let collector = parse_feed(&feed("crowdsec", FeedFormat::Crowdsec), &mut reader, now())?;
    assert_eq!(collector.summary.parsed, 1);
    assert_eq!(skipped(&collector, "invalid_utf8"), 1);
    Ok(())
}


#[test]
fn skip_samples_are_capped_but_the_count_is_not() -> TestResult {
    let text = "bad value!\n".repeat(MAX_REPORTED_SKIPS + EXTRA_SKIPS);
    let collector = parse_text(&feed("crowdsec", FeedFormat::Crowdsec), &text)?;
    assert_eq!(collector.summary.samples.len(), MAX_REPORTED_SKIPS);
    assert_eq!(skipped(&collector, "invalid_value"), (MAX_REPORTED_SKIPS + EXTRA_SKIPS) as u64);
    Ok(())
}


#[test]
fn an_object_over_the_cap_is_skipped_and_a_document_over_the_cap_is_refused() -> TestResult {
    let mut config = feed("list", FeedFormat::Json);
    config.mapping.value = Some("ioc".to_owned());
    let text = format!("[{{\"ioc\": \"{}\"}}, {{\"ioc\": \"192.0.2.1\"}}]", "a".repeat(MAX_OBJECT_BYTES));
    let collector = parse_text(&config, &text)?;
    assert_eq!(values_of(&collector), vec!["192.0.2.1".to_owned()]);
    assert_eq!(skipped(&collector, "object_too_large"), 1);
    let mut reader = BufReader::new(io::repeat(b' ').take(MAX_DOCUMENT_BYTES as u64 + 1));
    assert!(matches!(parse_feed(&config, &mut reader, now()), Err(FeedError::DocumentTooLarge)));
    Ok(())
}


#[test]
fn document_level_failures_are_typed() -> TestResult {
    let json = feed("list", FeedFormat::Json);
    let stix = feed("bundle", FeedFormat::Stix);
    assert!(matches!(parse_text(&json, "[1, 2"), Err(FeedError::Json(_))));
    assert!(matches!(parse_text(&json, "{}"), Err(FeedError::NotAnArray)));
    assert!(matches!(parse_text(&stix, "[]"), Err(FeedError::NotABundle)));
    assert!(matches!(parse_feed(&json, &mut BufReader::new(Broken), now()), Err(FeedError::Io(_))));
    assert!(matches!(
        parse_feed(&feed("crowdsec", FeedFormat::Crowdsec), &mut BufReader::new(Broken), now()),
        Err(FeedError::Io(_))
    ));
    Ok(())
}


#[test]
fn a_csv_record_that_cannot_be_read_is_a_typed_skip() -> TestResult {
    assert!(matches!(csv_record(&mut Broken), Err(EntryError::Csv(_))));
    assert_eq!(csv_record(&mut Broken).err().as_ref().map(reason_key), Some("malformed_csv"));
    assert_eq!(reason_key(&EntryError::UnsupportedPattern), "unsupported_pattern");
    Ok(())
}


#[test]
fn a_header_only_generic_csv_has_no_entries() -> TestResult {
    let mut config = feed("partner", FeedFormat::Csv);
    config.mapping.value = Some("indicator".to_owned());
    let collector = parse_text(&config, "indicator,kind\n")?;
    assert_eq!(collector.summary.parsed, 0);
    assert!(collector.summary.skipped.is_empty());
    Ok(())
}


#[test]
fn a_stix_object_over_the_cap_and_an_oversized_pattern_are_skipped() -> TestResult {
    let config = feed("bundle", FeedFormat::Stix);
    let big = "a".repeat(MAX_OBJECT_BYTES);
    let text = format!("{{\"objects\": [{{\"type\": \"indicator\", \"pattern\": \"[domain-name:value = '{big}']\"}}]}}");
    let collector = parse_text(&config, &text)?;
    assert_eq!(skipped(&collector, "object_too_large"), 1);
    Ok(())
}


#[test]
fn json_values_that_are_not_text_or_numbers_are_missing() -> TestResult {
    let mut config = feed("list", FeedFormat::Json);
    config.mapping.value = Some("a".to_owned());
    let collector = parse_text(&config, "[{\"a\": true}, {\"a\": null}, {\"a\": {}}, {\"a\": \"\"}]")?;
    assert_eq!(skipped(&collector, "missing_field"), JSON_NOT_TEXT);
    Ok(())
}


const CRAFTED_TIMES: [&str; 4] = [
    "9999-12-31T23:00:00-02:00",
    "9999-12-31T23:59:59-00:01",
    "0000-01-01T00:00:00+00:01",
    "0000-01-01T00:30:00+01:00",
];


#[test]
fn a_crafted_time_is_refused_and_counted_in_every_format() -> TestResult {
    CRAFTED_TIMES.iter().try_for_each(|crafted| crafted_time_case(crafted))
}


fn crafted_time_case(crafted: &str) -> TestResult {
    let mapping = Mapping {
        value: Some("ioc".to_owned()),
        first_seen: Some("seen".to_owned()),
        ..Mapping::default()
    };
    let mut csv = feed("generic", FeedFormat::Csv);
    csv.mapping = mapping.clone();
    let csv_text = format!("ioc,seen\nbad.example,{crafted}\ngood.example,2026-11-01T00:00:00Z\n");
    let mut json = feed("list", FeedFormat::Json);
    json.mapping = mapping;
    let json_text = format!(r#"[{{"ioc":"bad.example","seen":"{crafted}"}},{{"ioc":"good.example","seen":"2026-11-01T00:00:00Z"}}]"#);
    let stix_text = format!(
        r#"{{"objects":[{{"type":"indicator","pattern":"[domain-name:value = 'bad.example']","valid_from":"{crafted}"}},{{"type":"indicator","pattern":"[domain-name:value = 'good.example']","valid_from":"2026-11-01T00:00:00Z"}}]}}"#
    );
    let misp_text = format!(
        r#"{{"Event":{{"Attribute":[{{"type":"domain","value":"bad.example","to_ids":true,"first_seen":"{crafted}"}},{{"type":"domain","value":"good.example","to_ids":true}}]}}}}"#
    );
    let cases = [
        (csv, csv_text),
        (json, json_text),
        (feed("stix", FeedFormat::Stix), stix_text),
        (feed("misp", FeedFormat::Misp), misp_text),
    ];
    cases.iter().try_for_each(|(config, text)| -> TestResult {
        let collector = parse_text(config, text)?;
        assert_eq!(values_of(&collector), vec!["good.example".to_owned()], "{}", config.name);
        assert_eq!(skipped(&collector, "invalid_timestamp"), 1, "{}", config.name);
        Ok(())
    })
}
