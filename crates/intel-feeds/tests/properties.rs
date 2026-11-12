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
use intel_feeds::model::{IocType, RawEntry};
use intel_feeds::stix::parse_pattern;
use parsing::parse_text;
use proptest::prelude::*;
use support::feed;


const CASES: u32 = 512;


const MAX_PORT: u32 = 70_000;


const FIXTURE_VALUES: [(IocType, &str); 8] = [
    (IocType::Domain, "Example.COM."),
    (IocType::Domain, "xn--bcher-kva.example"),
    (IocType::Ipv6, "::ffff:1.2.3.4"),
    (IocType::Cidr, "10.1.2.3/16"),
    (IocType::Url, "HTTP://Example.com:80/a/../b?q=1#frag"),
    (IocType::Url, "foo://h/a\\b\"c"),
    (IocType::Md5, "D41D8CD98F00B204E9800998ECF8427E"),
    (IocType::Sha1, "DA39A3EE5E6B4B0D3255BFEF95601890AFD80709"),
];


fn is_idempotent(declared: IocType, raw: &str) -> bool {
    canonicalise(declared, raw).map_or(true, |first| {
        canonicalise(first.ioc_type, &first.value).is_ok_and(|second| second.ioc_type == first.ioc_type && second.value == first.value)
    })
}


#[test]
fn canonicalise_is_idempotent_on_the_fixture_values() -> Result<(), String> {
    let cases = FIXTURE_VALUES.iter().filter(|(declared, raw)| canonicalise(*declared, raw).is_err());
    assert_eq!(cases.count(), 0);
    assert!(FIXTURE_VALUES.iter().all(|(declared, raw)| is_idempotent(*declared, raw)));
    Ok(())
}


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
    fn canonicalise_is_idempotent_on_generated_urls_and_domains(
        host in "[A-Za-z0-9.-]{1,40}",
        path in "[ -~]{0,60}",
        port in 0u32..MAX_PORT,
    ) {
        prop_assert!(is_idempotent(IocType::Domain, &host));
        let url = format!("http://{host}:{port}/{path}");
        prop_assert!(is_idempotent(IocType::Url, &url));
        let other = format!("foo://{host}/{path}");
        prop_assert!(is_idempotent(IocType::Url, &other));
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
