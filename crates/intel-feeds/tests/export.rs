#[path = "common/clock.rs"]
mod clock;
#[path = "common/engine.rs"]
mod engine;
#[path = "common/fixtures.rs"]
mod fixtures;
#[path = "common/memory.rs"]
mod memory;
#[path = "common/noload.rs"]
mod noload;
#[path = "common/support.rs"]
mod support;
#[path = "common/types.rs"]
mod types;


use clock::now;
use core_config::load::load_file;
use core_config::reload::{current_config, reload, ReloadOutcome};
use engine::{engine_for, feeds_text, replace_file};
use fixtures::fixture;
use intel_feeds::cli::{run_command, Session};
use intel_feeds::config::{feeds_state, validate_feeds, ExportPolicy, FeedFormat, FeedsError, FeedsFile, EXPORT_KEY};
use intel_feeds::dedup::insert_ioc;
use intel_feeds::export::{
    build_bundle, escape_literal, export_bundle, indicator_id, indicator_of, pattern_of, tlp_marking, uuid_v5, ExportSummary, REASON_CONFIDENCE,
    REASON_TLP, REASON_TYPE,
};
use intel_feeds::formats::parse_feed;
use intel_feeds::limits::MAX_CONFIDENCE;
use intel_feeds::model::{Ioc, IocType, Source, Tags, Tlp};
use intel_feeds::run::{collect_feeds, open_file};
use intel_feeds::types::IocIndex;
use memory::{open_from, FailingWriter};
use noload::no_load;
use proptest::prelude::*;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::{self, Write};
use std::ops::ControlFlow;
use std::path::Path;
use support::feed;
use tempfile::tempdir;
use time::macros::datetime;
use time::OffsetDateTime;
use types::TestResult;
use uuid::Uuid;


const CASES: u32 = 512;


const FIRST_SEEN: OffsetDateTime = datetime!(2026-11-01 00:00:00 UTC);


const LAST_SEEN: OffsetDateTime = datetime!(2026-11-02 00:00:00 UTC);


const EXPIRES_AT: OffsetDateTime = datetime!(2026-11-09 00:00:00 UTC);


const OFFSET_FIRST_SEEN: OffsetDateTime = datetime!(2026-11-01 02:00:00 +02:00);


const MARKING_COUNT: usize = 5;


const TWO: u64 = 2;


const PYTHON_ORG_UUID: &str = "886313e1-3b8a-5372-9b90-0c9aee199e5d";


const UNREPRESENTABLE_YEAR: i32 = -1;


const LOW: u8 = 30;


const HIGH: u8 = 80;


const MIN: u8 = 50;


const TEN: u8 = 10;


const THREE: u64 = 3;


const EIGHT: u64 = 8;


const MD5: &str = "d41d8cd98f00b204e9800998ecf8427e";


const SHA1: &str = "da39a3ee5e6b4b0d3255bfef95601890afd80709";


const SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";


const RED_CEILING: ExportPolicy = ExportPolicy {
    max_tlp: Tlp::Red,
    min_confidence: 0,
    types: None,
};


struct NewlineFails;


impl Write for NewlineFails {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer == b"\n" {
            Err(io::Error::other("injected"))
        } else {
            Ok(buffer.len())
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn ioc(ioc_type: IocType, value: &str, tlp: Tlp, confidence: u8) -> Ioc {
    Ioc {
        ioc_type,
        value: value.to_owned(),
        sources: vec![Source {
            feed: "f".to_owned(),
            version: "1".to_owned(),
        }],
        first_seen: FIRST_SEEN,
        last_seen: LAST_SEEN,
        confidence,
        tlp,
        expires_at: Some(EXPIRES_AT),
        tags: Tags::default(),
    }
}


fn index_of(iocs: Vec<Ioc>) -> IocIndex {
    let mut index = IocIndex::new();
    iocs.into_iter().for_each(|item| {
        insert_ioc(&mut index, item);
    });
    index
}


fn exported_text(index: &IocIndex, policy: &ExportPolicy) -> Result<(String, ExportSummary), Box<dyn std::error::Error>> {
    let mut out = Vec::new();
    let summary = export_bundle(index, policy, &mut out)?;
    Ok((String::from_utf8(out)?, summary))
}


fn mixed_index() -> IocIndex {
    index_of(vec![
        ioc(IocType::Ipv4, "192.0.2.1", Tlp::Clear, HIGH),
        ioc(IocType::Domain, "a.example", Tlp::Green, LOW),
        ioc(IocType::Url, "http://a.example/x", Tlp::Amber, HIGH),
        ioc(IocType::Md5, MD5, Tlp::AmberStrict, HIGH),
        ioc(IocType::Sha1, SHA1, Tlp::Red, LOW),
    ])
}


#[test]
fn every_type_has_its_pattern() -> TestResult {
    let cases = [
        (IocType::Ipv4, "192.0.2.1", "[ipv4-addr:value = '192.0.2.1']"),
        (IocType::Ipv6, "2001:db8::1", "[ipv6-addr:value = '2001:db8::1']"),
        (IocType::Cidr, "10.0.0.0/8", "[ipv4-addr:value ISSUBSET '10.0.0.0/8']"),
        (IocType::Cidr, "2001:db8::/32", "[ipv6-addr:value ISSUBSET '2001:db8::/32']"),
        (IocType::Domain, "a.example", "[domain-name:value = 'a.example']"),
        (IocType::Url, "http://a.example/x", "[url:value = 'http://a.example/x']"),
        (IocType::Md5, MD5, "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']"),
        (IocType::Sha1, SHA1, "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']"),
        (
            IocType::Sha256,
            SHA256,
            "[file:hashes.'SHA-256' = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855']",
        ),
    ];
    cases
        .iter()
        .for_each(|(ioc_type, value, expected)| assert_eq!(pattern_of(*ioc_type, value), *expected));
    Ok(())
}


#[test]
fn uuid_v5_matches_the_rfc_vector() -> TestResult {
    assert_eq!(uuid_v5(&Uuid::NAMESPACE_DNS, "python.org").to_string(), PYTHON_ORG_UUID);
    Ok(())
}


#[test]
fn ids_and_bytes_are_stable() -> TestResult {
    let first = exported_text(&mixed_index(), &RED_CEILING)?;
    let reversed = index_of(vec![
        ioc(IocType::Sha1, SHA1, Tlp::Red, LOW),
        ioc(IocType::Md5, MD5, Tlp::AmberStrict, HIGH),
        ioc(IocType::Url, "http://a.example/x", Tlp::Amber, HIGH),
        ioc(IocType::Domain, "a.example", Tlp::Green, LOW),
        ioc(IocType::Ipv4, "192.0.2.1", Tlp::Clear, HIGH),
    ]);
    let second = exported_text(&reversed, &RED_CEILING)?;
    assert_eq!(first, second);
    assert_eq!(indicator_id(IocType::Ipv4, "192.0.2.1"), indicator_id(IocType::Ipv4, "192.0.2.1"));
    assert_ne!(indicator_id(IocType::Ipv4, "192.0.2.1"), indicator_id(IocType::Domain, "192.0.2.1"));
    let bundle = &serde_json::from_str::<Value>(&first.0)?;
    let ids: Vec<&str> = bundle["objects"]
        .as_array()
        .ok_or("objects")?
        .iter()
        .filter_map(|item| item["id"].as_str())
        .collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
    assert!(bundle["id"].as_str().is_some_and(|id| id.starts_with("bundle--")));
    Ok(())
}


#[test]
fn an_indicator_carries_times_confidence_labels_and_marking() -> TestResult {
    let mut tagged = ioc(IocType::Domain, "a.example", Tlp::Green, HIGH);
    tagged.tags = Tags {
        malware: vec!["emotet".to_owned()],
        actor: vec!["ta542".to_owned()],
        campaign: vec!["spring".to_owned()],
    };
    tagged.first_seen = OFFSET_FIRST_SEEN;
    let indicator = &serde_json::to_value(indicator_of(&tagged))?;
    assert_eq!(indicator["type"], "indicator");
    assert_eq!(indicator["spec_version"], "2.1");
    assert_eq!(indicator["pattern_type"], "stix");
    assert_eq!(indicator["valid_from"], "2026-11-01T00:00:00Z");
    assert_eq!(indicator["valid_until"], "2026-11-09T00:00:00Z");
    assert_eq!(indicator["confidence"], HIGH);
    assert_eq!(
        indicator["labels"],
        serde_json::json!(["malware:emotet", "actor:ta542", "campaign:spring"])
    );
    assert_eq!(indicator["object_marking_refs"], serde_json::json!([tlp_marking(Tlp::Green)]));
    let mut bare = ioc(IocType::Domain, "b.example", Tlp::Red, HIGH);
    bare.expires_at = None;
    let plain = serde_json::to_value(indicator_of(&bare))?;
    assert!(plain.get("valid_until").is_none() && plain.get("labels").is_none());
    let markings: BTreeSet<&str> = [Tlp::Clear, Tlp::Green, Tlp::Amber, Tlp::AmberStrict, Tlp::Red]
        .into_iter()
        .map(tlp_marking)
        .collect();
    assert_eq!(markings.len(), MARKING_COUNT);
    Ok(())
}


#[test]
fn the_default_policy_stops_at_amber_and_counts_refusals_per_reason() -> TestResult {
    let (_, summary) = exported_text(&mixed_index(), &ExportPolicy::default())?;
    assert_eq!(summary.exported, THREE);
    assert_eq!(summary.refused, BTreeMap::from([(REASON_TLP, TWO)]));
    let strict = ExportPolicy {
        max_tlp: Tlp::Red,
        min_confidence: MIN,
        types: Some(vec![IocType::Ipv4, IocType::Domain, IocType::Sha1]),
    };
    let (_, filtered) = exported_text(&mixed_index(), &strict)?;
    assert_eq!(filtered.exported, 1);
    assert_eq!(filtered.refused, BTreeMap::from([(REASON_CONFIDENCE, TWO), (REASON_TYPE, TWO)]));
    let (bundle, _) = build_bundle(
        &mixed_index(),
        &ExportPolicy {
            types: Some(Vec::new()),
            ..ExportPolicy::default()
        },
    );
    assert!(bundle.objects.is_empty());
    Ok(())
}


#[test]
fn writer_failures_and_unrepresentable_times_are_errors() -> TestResult {
    let index = mixed_index();
    assert!(export_bundle(&index, &ExportPolicy::default(), &mut FailingWriter).is_err());
    assert!(export_bundle(&index, &ExportPolicy::default(), &mut NewlineFails).is_err());
    let mut far = ioc(IocType::Ipv4, "192.0.2.9", Tlp::Clear, HIGH);
    far.expires_at = Some(OffsetDateTime::UNIX_EPOCH.replace_year(UNREPRESENTABLE_YEAR)?);
    assert!(export_bundle(&index_of(vec![far]), &ExportPolicy::default(), &mut Vec::new()).is_err());
    Ok(())
}


fn closing_quote(pattern: &str, from: usize) -> Option<(String, usize)> {
    let flow = pattern
        .char_indices()
        .skip(from)
        .try_fold((String::new(), false), |(mut decoded, escaped), (index, character)| {
            if escaped {
                decoded.push(character);
                ControlFlow::Continue((decoded, false))
            } else if character == '\\' {
                ControlFlow::Continue((decoded, true))
            } else if character == '\'' {
                ControlFlow::Break((decoded, index))
            } else {
                decoded.push(character);
                ControlFlow::Continue((decoded, false))
            }
        });
    match flow {
        ControlFlow::Break(found) => Some(found),
        ControlFlow::Continue(_) => None,
    }
}


#[test]
fn escaping_handles_both_special_characters() -> TestResult {
    assert_eq!(escape_literal("a'b\\c"), "a\\'b\\\\c");
    assert_eq!(pattern_of(IocType::Url, "http://a/'x"), "[url:value = 'http://a/\\'x']");
    assert_eq!(closing_quote("abc", 0), None);
    Ok(())
}


proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    #[test]
    fn no_value_can_close_the_pattern_literal(value in "[ -~\u{e9}]{0,60}") {
        let pattern = pattern_of(IocType::Url, &value);
        let opening = "[url:value = '".len();
        let found = closing_quote(&pattern, opening);
        prop_assert_eq!(found, Some((value.clone(), pattern.len() - "']".len())));
    }
}


#[test]
fn the_exported_bundle_parses_back_to_the_same_iocs() -> TestResult {
    let supported = index_of(vec![
        ioc(IocType::Ipv4, "192.0.2.1", Tlp::Clear, HIGH),
        ioc(IocType::Ipv6, "2001:db8::1", Tlp::Green, LOW),
        ioc(IocType::Domain, "a.example", Tlp::Amber, HIGH),
        ioc(IocType::Url, "http://a.example/x", Tlp::Amber, HIGH),
        ioc(IocType::Md5, MD5, Tlp::Clear, HIGH),
        ioc(IocType::Sha1, SHA1, Tlp::Clear, HIGH),
        ioc(IocType::Sha256, SHA256, Tlp::Clear, HIGH),
        ioc(IocType::Cidr, "10.0.0.0/8", Tlp::Clear, HIGH),
    ]);
    let (text, summary) = exported_text(&supported, &ExportPolicy::default())?;
    assert_eq!(summary.exported, EIGHT);
    let config = feed("stix", FeedFormat::Stix);
    let collector = parse_feed(&config, &mut text.as_bytes(), now())?;
    let mut back: Vec<(IocType, String)> = collector.iocs.iter().map(|item| (item.ioc_type, item.value.clone())).collect();
    back.sort();
    let expected: Vec<(IocType, String)> = supported
        .values()
        .filter(|item| item.ioc_type != IocType::Cidr)
        .map(|item| (item.ioc_type, item.value.clone()))
        .collect();
    assert_eq!(back, expected);
    assert_eq!(collector.summary.unsupported, 1);
    assert!(collector.iocs.iter().all(|item| item.first_seen == FIRST_SEEN));
    assert_eq!(collector.iocs.iter().map(|item| item.confidence).max(), Some(HIGH));
    Ok(())
}


fn fixture_bundle() -> Result<String, Box<dyn std::error::Error>> {
    let config: FeedsFile = load_file(&fixture("feeds.yaml"))?;
    let base = fixture("feeds.yaml").parent().map(Path::to_path_buf).ok_or("no parent")?;
    let (index, _) = collect_feeds(&config, now(), &|path| open_file(&base.join(path)));
    Ok(exported_text(&index, &config.export)?.0)
}


#[test]
fn the_fixture_bundle_matches_its_snapshot() -> TestResult {
    let expected = fs::read_to_string(fixture("expected-bundle.json"))?;
    assert_eq!(fixture_bundle()?, expected);
    assert_eq!(fixture_bundle()?, fixture_bundle()?);
    Ok(())
}


#[test]
fn the_export_policy_is_validated_and_reloaded_without_restart() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    replace_file(&path, &feeds_text(""))?;
    let running = engine_for(&path)?;
    assert_eq!(current_config(&running).export, ExportPolicy::default());
    assert_eq!(current_config(&running).export.max_tlp, Tlp::Amber);
    assert!(feeds_state(&current_config(&running)).contains_key(EXPORT_KEY));
    replace_file(
        &path,
        &format!("{}export:\n  max_tlp: green\n  min_confidence: 10\n  types: [ipv4]\n", feeds_text("")),
    )?;
    assert_eq!(
        reload(&running),
        ReloadOutcome::Applied {
            keys: vec![EXPORT_KEY.to_owned()]
        }
    );
    let policy = current_config(&running).export.clone();
    assert_eq!(
        (policy.max_tlp, policy.min_confidence, policy.types),
        (Tlp::Green, TEN, Some(vec![IocType::Ipv4]))
    );
    replace_file(&path, &format!("{}export:\n  min_confidence: 101\n", feeds_text("")))?;
    assert!(matches!(reload(&running), ReloadOutcome::Refused { reason } if reason.contains("minimum confidence")));
    replace_file(&path, &format!("{}export:\n  surprise: 1\n", feeds_text("")))?;
    assert!(matches!(reload(&running), ReloadOutcome::Refused { .. }));
    assert_eq!(current_config(&running).export.max_tlp, Tlp::Green);
    let invalid = FeedsFile {
        export: ExportPolicy {
            min_confidence: MAX_CONFIDENCE + 1,
            ..ExportPolicy::default()
        },
        ..FeedsFile::default()
    };
    assert!(matches!(validate_feeds(&invalid), Err(FeedsError::ExportConfidence)));
    Ok(())
}


#[test]
fn the_export_command_follows_the_live_policy() -> TestResult {
    let dir = tempdir()?;
    let path = dir.path().join("feeds.yaml");
    let text = "  - name: base\n    format: crowdsec\n    path: base.txt\n";
    replace_file(&path, &format!("feeds:\n{text}"))?;
    let running = engine_for(&path)?;
    let files = BTreeMap::from([("base.txt", "192.0.2.1\n")]);
    let open = |file: &Path| open_from(&files, file);
    let run_export = |out: &mut Vec<u8>, report: &mut Vec<u8>| -> io::Result<()> {
        let mut session = Session {
            engine: &running,
            clock: &now,
            open: &open,
            load: &no_load,
            out,
            report,
        };
        run_command(&mut session, "export")
    };
    let (mut out, mut report) = (Vec::new(), Vec::new());
    run_export(&mut out, &mut report)?;
    assert_eq!(
        serde_json::from_slice::<Value>(&out)?
            .get("objects")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    assert!(String::from_utf8(report)?.contains("\"exported\":1"));
    replace_file(&path, &format!("feeds:\n{text}export:\n  max_tlp: clear\n"))?;
    assert!(matches!(reload(&running), ReloadOutcome::Applied { .. }));
    let (mut lowered, mut lowered_report) = (Vec::new(), Vec::new());
    run_export(&mut lowered, &mut lowered_report)?;
    assert_eq!(
        serde_json::from_slice::<Value>(&lowered)?
            .get("objects")
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(0)
    );
    assert!(String::from_utf8(lowered_report)?.contains("\"tlp_above_ceiling\":1"));
    let mut failing = Session {
        engine: &running,
        clock: &now,
        open: &open,
        load: &no_load,
        out: &mut FailingWriter,
        report: &mut Vec::new(),
    };
    assert!(run_command(&mut failing, "export").is_err());
    let mut sink = Vec::new();
    let mut bad_report = Session {
        engine: &running,
        clock: &now,
        open: &open,
        load: &no_load,
        out: &mut sink,
        report: &mut FailingWriter,
    };
    assert!(run_command(&mut bad_report, "export").is_err());
    Ok(())
}
