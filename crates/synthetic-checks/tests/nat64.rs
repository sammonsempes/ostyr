#[path = "common/types.rs"]
mod types;


use core_config::parse::parse_document;
use ipnet::{IpNet, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use synthetic_checks::error::{AddressClass, GuardError, ProbeError};
use synthetic_checks::model::CheckFile;
use synthetic_checks::probe::{guarded_addresses, http_probe, probe_limits, with_nat64_prefix, HttpTransports};
use synthetic_checks::target::{embedded_v4, guard_address, guard_address_nat64, rfc6052_v4, V4_OCTETS};
use types::TestResult;
use url::Host;


const FILE_NAME: &str = "checks.yaml";


const FULL_LENGTH: u8 = 128;


const SLASH_64: u8 = 64;


const METADATA_OCTETS: [u8; V4_OCTETS] = [169, 254, 169, 254];


const LIMIT_SECONDS: u64 = 5;


fn ip(text: &str) -> Result<IpAddr, Box<dyn std::error::Error>> {
    Ok(text.parse()?)
}


fn prefix(text: &str) -> Result<Ipv6Net, Box<dyn std::error::Error>> {
    Ok(text.parse()?)
}


fn class_of(text: &str, scope: &[IpNet], nat64: Option<Ipv6Net>) -> Result<Option<AddressClass>, Box<dyn std::error::Error>> {
    match guard_address_nat64(ip(text)?, scope, nat64) {
        Ok(_) => Ok(None),
        Err(GuardError::Refused { class, .. }) => Ok(Some(class)),
        Err(GuardError::BadPrefix(error)) => Err(error.into()),
    }
}


#[test]
fn declared_prefixes_of_every_length_refuse_the_embedded_metadata_address() -> TestResult {
    let cases = [
        ("2001:db8:a9fe:a9fe:0:1::", "2001:db8::/32", AddressClass::Metadata),
        ("2001:db8:1a9:fea9:fe::", "2001:db8:100::/40", AddressClass::Metadata),
        ("2001:db8:1:a9fe:a9:fe00::", "2001:db8:1::/48", AddressClass::Metadata),
        ("2001:db8:1:a9:fe:a9fe::", "2001:db8:1::/56", AddressClass::Metadata),
        ("2001:db8:1:2:a9:fea9:fe00:0", "2001:db8:1:2::/64", AddressClass::Metadata),
        ("2001:db8:1:2:7f:1::", "2001:db8:1:2::/64", AddressClass::Loopback),
        ("2001:db8:1::a9fe:a9fe", "2001:db8:1::/96", AddressClass::Metadata),
    ];
    cases.iter().try_for_each(|(address, declared, class)| -> TestResult {
        assert_eq!(class_of(address, &[], Some(prefix(declared)?))?, Some(*class), "{address}");
        assert_eq!(
            class_of(address, &[net_all()?], Some(prefix(declared)?))?.is_some(),
            *class == AddressClass::Metadata || *class == AddressClass::Unspecified,
            "{address}"
        );
        Ok(())
    })
}


fn net_all() -> Result<IpNet, Box<dyn std::error::Error>> {
    Ok("2001:db8::/32".parse()?)
}


#[test]
fn without_a_declared_prefix_a_non_96_embedding_is_not_detected() -> TestResult {
    assert_eq!(class_of("2001:db8:1:2:a9:fea9:fe00:0", &[], None)?, None);
    assert!(guard_address(ip("2001:db8:1:2:a9:fea9:fe00:0")?, &[]).is_ok());
    Ok(())
}


#[test]
fn a_public_address_in_a_declared_prefix_passes() -> TestResult {
    let declared = Some(prefix("2001:db8:1:2::/64")?);
    assert_eq!(class_of("2001:db8:1:2:5d:b8d8:2200:0", &[], declared)?, None);
    assert_eq!(class_of("2606:4700:4700::1111", &[], declared)?, None);
    Ok(())
}


#[test]
fn rfc6052_positions_skip_the_u_octet() -> TestResult {
    let octets = "2001:db8:1:2:a9:fea9:fe00:0".parse::<std::net::Ipv6Addr>()?.octets();
    assert_eq!(rfc6052_v4(octets, SLASH_64), Some(Ipv4Addr::from(METADATA_OCTETS)));
    assert_eq!(rfc6052_v4(octets, FULL_LENGTH), None);
    Ok(())
}


#[test]
fn a_96_embedding_of_the_zero_network_is_refused_but_a_low_host_number_passes() -> TestResult {
    assert_eq!(class_of("2001:db8:64::", &[], None)?, Some(AddressClass::Unspecified));
    assert_eq!(class_of("2001:db8:64::ff:ffff", &[], None)?, Some(AddressClass::Reserved));
    assert_eq!(class_of("2001:db8:64::ff:ffff", &["2001:db8::/32".parse()?], None)?, None);
    assert_eq!(class_of("2606:4700:4700::1111", &[], None)?, None);
    assert_eq!(class_of("2606:2800:220:1::1", &[], None)?, None);
    Ok(())
}


#[test]
fn isatap_interface_identifiers_have_their_ipv4_classified() -> TestResult {
    assert_eq!(class_of("2001:db8::5efe:a00:1", &[], None)?, Some(AddressClass::Private));
    assert_eq!(class_of("2001:db8::200:5efe:a9fe:a9fe", &[], None)?, Some(AddressClass::Metadata));
    assert_eq!(
        class_of("2001:db8::200:5efe:a9fe:a9fe", &["2001:db8::/32".parse()?], None)?,
        Some(AddressClass::Metadata)
    );
    assert_eq!(class_of("2001:db8::200:5efe:5db8:d822", &[], None)?, None);
    assert_eq!(class_of("2001:db8::100:5efe:a00:1", &[], None)?, None);
    assert_eq!(embedded_v4(ip("2001:db8::5efe:7f00:1")?), vec![Ipv4Addr::LOCALHOST]);
    Ok(())
}


fn parse(extra: &str) -> Result<CheckFile, core_config::error::ConfigError> {
    let text = format!("checks:\n  - name: web\n    kind: dns\n    target: example.org\n    locations: [paris]\n{extra}\n");
    parse_document(&text, FILE_NAME)
}


#[test]
fn the_check_field_accepts_every_rfc_6052_length() -> TestResult {
    [
        "2001:db8::/32",
        "2001:db8::/40",
        "2001:db8::/48",
        "2001:db8::/56",
        "2001:db8::/64",
        "2001:db8::/96",
    ]
    .iter()
    .try_for_each(|declared| -> TestResult {
        let file = parse(&format!("    nat64_prefix: {declared}"))?;
        assert_eq!(file.checks.first().ok_or("no check")?.nat64_prefix, Some(prefix(declared)?));
        Ok(())
    })?;
    assert_eq!(parse("")?.checks.first().ok_or("no check")?.nat64_prefix, None);
    Ok(())
}


#[test]
fn an_invalid_prefix_is_refused_at_validation() -> TestResult {
    ["2001:db8::/33", "2001:db8::/128", "2001:db8::/0", "2001:db8:0:1::/32"]
        .iter()
        .try_for_each(|declared| -> TestResult {
            let error = parse(&format!("    nat64_prefix: {declared}")).err().ok_or("expected an error")?;
            assert!(error.to_string().contains("nat64_prefix"), "{declared}: {error}");
            Ok(())
        })?;
    let limits = probe_limits(Duration::from_secs(LIMIT_SECONDS), 1, 0)?;
    assert!(with_nat64_prefix(limits, Some(prefix("2001:db8::/33")?)).is_err());
    assert!(with_nat64_prefix(limits, Some(prefix("2001:db8::/32")?)).is_ok());
    assert!(with_nat64_prefix(limits, None).is_ok());
    Ok(())
}


#[test]
fn the_http_probe_guards_with_the_declared_prefix() -> TestResult {
    let limits = with_nat64_prefix(
        probe_limits(Duration::from_secs(LIMIT_SECONDS), 1, 0)?,
        Some(prefix("2001:db8:1:2::/64")?),
    )?;
    let answer = ip("2001:db8:1:2:a9:fea9:fe00:0")?;
    let resolve = |_: &str, _: Duration, _: usize| -> std::io::Result<Vec<IpAddr>> { Ok(vec![answer]) };
    let fetch = |_: &_, _: Duration, _: _| -> std::io::Result<_> { Err(std::io::Error::other("must not connect")) };
    let clock = || Duration::ZERO;
    let transports = HttpTransports {
        resolve: &resolve,
        fetch: &fetch,
        clock: &clock,
    };
    let error = http_probe("http://nat.example/", &[], &limits, &transports)
        .err()
        .ok_or("expected a refusal")?;
    assert!(matches!(error, ProbeError::Refused(_)), "{error}");
    Ok(())
}


#[test]
fn an_unsupported_prefix_length_is_a_typed_refusal_in_both_guards() -> TestResult {
    let public = ip("2606:4700:4700::1111")?;
    ["2001:db8::1/128", "2001:db8::/33", "2001:db8::/0"]
        .iter()
        .try_for_each(|declared| -> TestResult {
            let net = Some(prefix(declared)?);
            assert!(
                matches!(guard_address_nat64(public, &[], net), Err(GuardError::BadPrefix(_))),
                "{declared}"
            );
            let resolve = |_: &str, _: Duration, _: usize| -> std::io::Result<Vec<IpAddr>> { Ok(vec![public]) };
            let outcome = guarded_addresses(Host::Ipv6("2606:4700:4700::1111".parse()?), &[], net, &resolve, Duration::ZERO);
            assert!(matches!(outcome, Err(ProbeError::Refused(GuardError::BadPrefix(_)))), "{declared}");
            Ok(())
        })
}


#[test]
fn an_invalid_prefix_refuses_a_name_that_resolves_to_nothing() -> TestResult {
    let called = AtomicBool::new(false);
    let resolve = |_: &str, _: Duration, _: usize| -> std::io::Result<Vec<IpAddr>> {
        called.store(true, Ordering::SeqCst);
        Ok(vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))])
    };
    let outcome = guarded_addresses(
        Host::Domain("empty.example"),
        &[],
        Some(prefix("2001:db8::/33")?),
        &resolve,
        Duration::ZERO,
    );
    assert!(matches!(outcome, Err(ProbeError::Refused(GuardError::BadPrefix(_)))));
    assert!(!called.load(Ordering::SeqCst));
    let valid = guarded_addresses(Host::Domain("empty.example"), &[], None, &resolve, Duration::ZERO)?;
    assert!(called.load(Ordering::SeqCst));
    assert_eq!(valid.len(), 1);
    Ok(())
}
