#[path = "common/clock.rs"]
mod clock;
#[path = "common/parsing.rs"]
mod parsing;
#[path = "common/support.rs"]
mod support;


use clock::now;
use intel_feeds::canon::canonicalise;
use intel_feeds::config::FeedFormat;
use intel_feeds::entry::build_ioc;
use intel_feeds::model::RawEntry;
use intel_feeds::stix::parse_pattern;
use parsing::parse_text;
use proptest::prelude::*;
use support::feed;


const CASES: u32 = 512;


proptest! {
    #![proptest_config(ProptestConfig::with_cases(CASES))]

    #[test]
    fn random_text_never_panics_and_only_canonical_values_come_out(text in "[ -~\n\t\u{e9}\u{fc}]{0,400}") {
        let formats = [
            FeedFormat::Crowdsec,
            FeedFormat::AbuseChUrlhaus,
            FeedFormat::AbuseChThreatfox,
            FeedFormat::AbuseChFeodo,
            FeedFormat::Csv,
            FeedFormat::Json,
            FeedFormat::Stix,
        ];
        formats.iter().for_each(|format| {
            let mut config = feed("random", *format);
            config.mapping.value = Some("a".to_owned());
            if let Ok(collector) = parse_text(&config, &text) {
                collector.iocs.iter().for_each(|ioc| {
                    let again = canonicalise(ioc.ioc_type, &ioc.value).map(|canonical| (canonical.ioc_type, canonical.value));
                    assert_eq!(again.ok(), Some((ioc.ioc_type, ioc.value.clone())));
                });
            }
        });
    }

    #[test]
    fn random_values_and_patterns_never_panic(text in "[ -~\u{e9}\u{fc}]{0,400}") {
        let raw = RawEntry { value: text.clone(), ..RawEntry::default() };
        let built = build_ioc(&feed("random", FeedFormat::Csv), &raw, now());
        if let Ok(ioc) = built {
            prop_assert_eq!(canonicalise(ioc.ioc_type, &ioc.value).map(|canonical| canonical.value).ok(), Some(ioc.value));
        }
        if let Some(terms) = parse_pattern(&text) {
            prop_assert!(terms.iter().all(|term| text.contains(&term.value)));
        }
    }
}
