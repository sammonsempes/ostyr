#[path = "common/types.rs"]
mod types;


use intel_feeds::canon::{canonicalise, detect_type, hash_type_of_length, type_from_name};
use intel_feeds::error::CanonError;
use intel_feeds::model::IocType;
use types::TestResult;


const LABEL_LENGTH: usize = 63;


const LABEL_COUNT: usize = 5;


const URL_PADDING: usize = 3_000;


const MD5_TEXT: &str = "D41D8CD98F00B204E9800998ECF8427E";


fn value_of(ioc_type: IocType, raw: &str) -> Result<(IocType, String), CanonError> {
    canonicalise(ioc_type, raw).map(|canonical| (canonical.ioc_type, canonical.value))
}


#[test]
fn addresses_are_canonical_and_ipv4_mapped_becomes_ipv4() -> TestResult {
    assert_eq!(value_of(IocType::Ipv4, " 192.0.2.1 ")?, (IocType::Ipv4, "192.0.2.1".to_owned()));
    assert_eq!(value_of(IocType::Ipv6, "2001:DB8:0:0::5")?, (IocType::Ipv6, "2001:db8::5".to_owned()));
    assert_eq!(value_of(IocType::Ipv6, "::ffff:192.0.2.77")?, (IocType::Ipv4, "192.0.2.77".to_owned()));
    assert!(matches!(value_of(IocType::Ipv4, "300.1.1.1"), Err(CanonError::Address(_))));
    Ok(())
}


#[test]
fn networks_lose_their_host_bits() -> TestResult {
    assert_eq!(value_of(IocType::Cidr, "10.1.2.3/8")?, (IocType::Cidr, "10.0.0.0/8".to_owned()));
    assert_eq!(value_of(IocType::Cidr, "2001:DB8::1/32")?, (IocType::Cidr, "2001:db8::/32".to_owned()));
    assert!(matches!(value_of(IocType::Cidr, "1.2.3.4/33"), Err(CanonError::Network(_))));
    Ok(())
}


#[test]
fn domains_are_lowercase_punycode_without_trailing_dot() -> TestResult {
    assert_eq!(
        value_of(IocType::Domain, "Mixed.Example.COM.")?,
        (IocType::Domain, "mixed.example.com".to_owned())
    );
    assert_eq!(
        value_of(IocType::Domain, "B\u{fc}cher.example")?,
        (IocType::Domain, "xn--bcher-kva.example".to_owned())
    );
    assert!(matches!(value_of(IocType::Domain, "bad value!"), Err(CanonError::Domain(_))));
    assert!(matches!(value_of(IocType::Domain, "."), Err(CanonError::Domain(_))));
    let long = vec!["a".repeat(LABEL_LENGTH); LABEL_COUNT].join(".");
    assert!(matches!(value_of(IocType::Domain, &long), Err(CanonError::Domain(_))));
    Ok(())
}


#[test]
fn urls_are_parsed_and_lose_their_fragment() -> TestResult {
    assert_eq!(
        value_of(IocType::Url, "HTTP://Evil.Example.com:80/a/../b?q=1#frag")?,
        (IocType::Url, "http://evil.example.com/b?q=1".to_owned())
    );
    assert!(matches!(value_of(IocType::Url, "not a url"), Err(CanonError::Url(_))));
    assert!(matches!(value_of(IocType::Url, "mailto:someone@example.com"), Err(CanonError::UrlShape)));
    let long = format!("http://example.com/{}", "a".repeat(URL_PADDING));
    assert!(matches!(value_of(IocType::Url, &long), Err(CanonError::UrlShape)));
    Ok(())
}


#[test]
fn hashes_are_lowercase_hex_of_the_exact_length() -> TestResult {
    assert_eq!(value_of(IocType::Md5, MD5_TEXT)?, (IocType::Md5, MD5_TEXT.to_ascii_lowercase()));
    assert!(matches!(value_of(IocType::Md5, "abc"), Err(CanonError::Hash { .. })));
    assert!(matches!(value_of(IocType::Sha1, MD5_TEXT), Err(CanonError::Hash { .. })));
    assert!(matches!(
        value_of(IocType::Sha256, &"g".repeat(hash_length(IocType::Sha256))),
        Err(CanonError::Hash { .. })
    ));
    assert!(value_of(IocType::Sha1, &"A".repeat(hash_length(IocType::Sha1))).is_ok());
    assert!(value_of(IocType::Sha256, &"b".repeat(hash_length(IocType::Sha256))).is_ok());
    Ok(())
}


fn hash_length(ioc_type: IocType) -> usize {
    (1..=intel_feeds::limits::SHA256_HEX_LENGTH)
        .find(|length| hash_type_of_length(*length) == ioc_type)
        .unwrap_or(0)
}


#[test]
fn types_are_detected_from_the_value() -> TestResult {
    assert_eq!(detect_type("http://x.example/a"), IocType::Url);
    assert_eq!(detect_type("10.0.0.0/8"), IocType::Cidr);
    assert_eq!(detect_type("192.0.2.1"), IocType::Ipv4);
    assert_eq!(detect_type("2001:db8::1"), IocType::Ipv6);
    assert_eq!(detect_type(MD5_TEXT), IocType::Md5);
    assert_eq!(detect_type(&"a".repeat(hash_length(IocType::Sha1))), IocType::Sha1);
    assert_eq!(detect_type(&"a".repeat(hash_length(IocType::Sha256))), IocType::Sha256);
    assert_eq!(detect_type("abc"), IocType::Domain);
    assert_eq!(detect_type("evil.example"), IocType::Domain);
    Ok(())
}


#[test]
fn type_names_of_feeds_are_understood() -> TestResult {
    let names = [
        ("ipv4", IocType::Ipv4),
        ("IPv6-addr", IocType::Ipv6),
        ("network", IocType::Cidr),
        ("FQDN", IocType::Domain),
        ("url", IocType::Url),
        ("md5_hash", IocType::Md5),
        ("sha-1", IocType::Sha1),
        ("sha256_hash", IocType::Sha256),
    ];
    names
        .iter()
        .for_each(|(name, expected)| assert_eq!(type_from_name(name), Some(*expected), "{name}"));
    assert_eq!(type_from_name("ip:port"), None);
    Ok(())
}


fn assert_too_broad(ioc_type: IocType, value: &str) {
    assert!(matches!(value_of(ioc_type, value), Err(CanonError::TooBroad)), "{value}");
}


#[test]
fn embedded_ipv4_networks_are_judged_by_their_ipv4_breadth() -> TestResult {
    [
        "::ffff:0.0.0.0/96",
        "::ffff:0:0/100",
        "::ffff:0:0/103",
        "::ffff:0:0/32",
        "::/32",
        "::/48",
        "::/100",
        "64:ff9b::/96",
        "64:ff9b::/103",
        "::/96",
        "::ffff:0:0/95",
        "64:ff9b::/95",
        "64:ff9b::/64",
        "64:ff9b::/32",
        "64:ff9b::/16",
        "64:ff9b:1::/48",
        "64:ff9b:1::/96",
        "64:ff9b:1::/100",
        "64:ff9b:1::/103",
        "64:ff9b:1:8000::/49",
        "64:ff9b:1:ffff::/64",
        "64:ff9b:1::/64",
        "::/95",
        "::/64",
    ]
    .iter()
    .for_each(|value| assert_too_broad(IocType::Cidr, value));
    assert_too_broad(IocType::Cidr, "10.0.0.0/7");
    assert_eq!(value_of(IocType::Cidr, "::ffff:10.0.0.0/104")?, (IocType::Cidr, "10.0.0.0/8".to_owned()));
    assert_eq!(value_of(IocType::Cidr, "::ffff:10.1.2.3/128")?, (IocType::Cidr, "10.1.2.3/32".to_owned()));
    assert_eq!(value_of(IocType::Cidr, "64:ff9b::a00:0/104")?.1, "64:ff9b::a00:0/104");
    assert_eq!(value_of(IocType::Cidr, "64:ff9b:1::a00:0/104")?.1, "64:ff9b:1::a00:0/104");
    assert_eq!(value_of(IocType::Cidr, "::a00:0/104")?.1, "::a00:0/104");
    assert_eq!(value_of(IocType::Cidr, "2001:db8::/32")?.1, "2001:db8::/32");
    Ok(())
}


#[test]
fn public_suffixes_and_single_labels_are_refused() -> TestResult {
    ["com", "co.uk", "github.io", "localhost", "com."]
        .iter()
        .for_each(|value| assert_too_broad(IocType::Domain, value));
    assert_eq!(value_of(IocType::Domain, "example.co.uk")?.1, "example.co.uk");
    assert_eq!(value_of(IocType::Domain, "evil.github.io")?.1, "evil.github.io");
    Ok(())
}


const EMBEDDING_SEEDS: [u128; 4] = [
    0x0000_0000_0000_0000_0000_ffff_0000_0000,
    0,
    0x0064_ff9b_0000_0000_0000_0000_0000_0000,
    0x0064_ff9b_0001_0000_0000_0000_0000_0000,
];


const MAX_PREFIX: u8 = 128;


fn is_refused(address: u128, prefix: u8) -> bool {
    let text = format!("{}/{prefix}", std::net::Ipv6Addr::from(address));
    matches!(value_of(IocType::Cidr, &text), Err(CanonError::TooBroad))
}


#[test]
fn every_local_use_nat64_prefix_between_49_and_103_is_refused() -> TestResult {
    (LOCAL_FIRST_PREFIX..LOCAL_ACCEPTED_PREFIX).for_each(|prefix| {
        assert!(is_refused(LOCAL_NAT64, prefix), "/{prefix}");
        assert!(is_refused(LOCAL_NAT64_UPPER, prefix), "upper half /{prefix}");
    });
    assert!(!is_refused(LOCAL_NAT64, LOCAL_ACCEPTED_PREFIX));
    Ok(())
}


const LOCAL_NAT64: u128 = 0x0064_ff9b_0001_0000_0000_0000_0000_0000;


const LOCAL_NAT64_UPPER: u128 = 0x0064_ff9b_0001_8000_0000_0000_0000_0000;


const LOCAL_FIRST_PREFIX: u8 = 49;


const LOCAL_ACCEPTED_PREFIX: u8 = 104;


#[test]
fn refusal_of_embedding_networks_is_monotonic() -> TestResult {
    let mut state: u64 = SEED;
    (0..EMBEDDING_SEEDS.len() * PROPERTY_ROUNDS).try_for_each(|round| -> TestResult {
        state = state.wrapping_mul(LCG_MULTIPLIER).wrapping_add(LCG_INCREMENT);
        let seed = EMBEDDING_SEEDS.get(round % EMBEDDING_SEEDS.len()).ok_or("no seed")?;
        let address = seed | u128::from(state >> LOW_SHIFT);
        let prefix = u8::try_from(state % u64::from(MAX_PREFIX + 1))?;
        (0..prefix)
            .filter(|_| is_refused(address, prefix))
            .for_each(|shorter| assert!(is_refused(address, shorter), "{address:x}/{prefix} refused but /{shorter} not"));
        Ok(())
    })
}


const PROPERTY_ROUNDS: usize = 500;


const LOW_SHIFT: u32 = 32;


const SEED: u64 = 0x2545_f491_4f6c_dd1d;


const LCG_MULTIPLIER: u64 = 6_364_136_223_846_793_005;


const LCG_INCREMENT: u64 = 1_442_695_040_888_963_407;
