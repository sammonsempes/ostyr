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
