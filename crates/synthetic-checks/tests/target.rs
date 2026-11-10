#[path = "common/types.rs"]
mod types;


use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use synthetic_checks::error::AddressClass;
use synthetic_checks::target::{checked_ip, embedded_v4, guard_address, probe_socket};
use types::TestResult;


const PORT: u16 = 443;


fn ip(text: &str) -> Result<IpAddr, Box<dyn std::error::Error>> {
    Ok(text.parse()?)
}


fn net(text: &str) -> Result<IpNet, Box<dyn std::error::Error>> {
    Ok(text.parse()?)
}


fn refused_class(text: &str, scope: &[IpNet]) -> Result<AddressClass, Box<dyn std::error::Error>> {
    let error = guard_address(ip(text)?, scope).err().ok_or("expected a refusal")?;
    match error {
        synthetic_checks::error::GuardError::Refused { class, .. } => Ok(class),
        synthetic_checks::error::GuardError::BadPrefix(_) => Err("unexpected prefix error".into()),
    }
}


#[test]
fn each_class_is_refused() -> TestResult {
    let cases = [
        ("127.0.0.1", AddressClass::Loopback),
        ("::1", AddressClass::Loopback),
        ("10.1.2.3", AddressClass::Private),
        ("172.16.0.1", AddressClass::Private),
        ("192.168.1.1", AddressClass::Private),
        ("169.254.1.1", AddressClass::LinkLocal),
        ("fe80::1", AddressClass::LinkLocal),
        ("fd12::1", AddressClass::UniqueLocal),
        ("224.0.0.1", AddressClass::Multicast),
        ("ff02::1", AddressClass::Multicast),
        ("0.0.0.0", AddressClass::Unspecified),
        ("::", AddressClass::Unspecified),
        ("169.254.169.254", AddressClass::Metadata),
        ("fd00:ec2::254", AddressClass::Metadata),
        ("100.100.100.200", AddressClass::Metadata),
        ("192.0.0.192", AddressClass::Metadata),
        ("168.63.129.16", AddressClass::Metadata),
        ("169.254.170.2", AddressClass::Metadata),
        ("100.64.0.1", AddressClass::Reserved),
        ("0.1.2.3", AddressClass::Reserved),
        ("240.0.0.1", AddressClass::Reserved),
        ("255.255.255.255", AddressClass::Reserved),
        ("192.0.0.1", AddressClass::Reserved),
        ("fec0::1", AddressClass::Reserved),
    ];
    cases.iter().try_for_each(|(text, class)| -> TestResult {
        assert_eq!(refused_class(text, &[])?, *class, "{text}");
        Ok(())
    })
}


#[test]
fn ipv4_mapped_forms_are_unwrapped() -> TestResult {
    assert_eq!(refused_class("::ffff:127.0.0.1", &[])?, AddressClass::Loopback);
    assert_eq!(refused_class("::ffff:10.0.0.1", &[])?, AddressClass::Private);
    assert_eq!(
        refused_class("::ffff:169.254.169.254", &[net("169.254.0.0/16")?])?,
        AddressClass::Metadata
    );
    let mapped_public = guard_address(ip("::ffff:93.184.216.34")?, &[])?;
    assert_eq!(checked_ip(&mapped_public), ip("93.184.216.34")?);
    Ok(())
}


#[test]
fn public_addresses_pass() -> TestResult {
    assert_eq!(checked_ip(&guard_address(ip("93.184.216.34")?, &[])?), ip("93.184.216.34")?);
    assert_eq!(checked_ip(&guard_address(ip("2606:2800:220:1::1")?, &[])?), ip("2606:2800:220:1::1")?);
    Ok(())
}


#[test]
fn scope_allows_one_network_and_not_its_neighbour() -> TestResult {
    let scope = [net("10.1.0.0/24")?];
    assert_eq!(checked_ip(&guard_address(ip("10.1.0.5")?, &scope)?), ip("10.1.0.5")?);
    assert_eq!(refused_class("10.1.1.5", &scope)?, AddressClass::Private);
    assert_eq!(checked_ip(&guard_address(ip("::ffff:10.1.0.5")?, &scope)?), ip("10.1.0.5")?);
    Ok(())
}


#[test]
fn scope_never_allows_metadata() -> TestResult {
    let scope = [net("169.254.0.0/16")?, net("fd00::/8")?];
    assert_eq!(refused_class("169.254.169.254", &scope)?, AddressClass::Metadata);
    assert_eq!(refused_class("fd00:ec2::254", &scope)?, AddressClass::Metadata);
    assert_eq!(checked_ip(&guard_address(ip("169.254.1.1")?, &scope)?), ip("169.254.1.1")?);
    Ok(())
}


#[test]
fn refusal_message_names_address_and_class() -> TestResult {
    let error = guard_address(ip("10.0.0.1")?, &[]).err().ok_or("expected a refusal")?;
    assert_eq!(error.to_string(), "address 10.0.0.1 is refused: Private and not in the declared scope");
    Ok(())
}


#[test]
fn probe_takes_the_checked_address_only() -> TestResult {
    let checked = guard_address(ip("93.184.216.34")?, &[])?;
    assert_eq!(probe_socket(checked, PORT), SocketAddr::new(ip("93.184.216.34")?, PORT));
    Ok(())
}


#[test]
fn embedded_ipv4_forms_are_refused() -> TestResult {
    let cases = [
        ("64:ff9b::a00:5", AddressClass::Private),
        ("64:ff9b::a9fe:a9fe", AddressClass::Metadata),
        ("64:ff9b::7f00:1", AddressClass::Loopback),
        ("::ffff:0:a00:5", AddressClass::Private),
        ("::ffff:0:a9fe:a9fe", AddressClass::Metadata),
        ("::7f00:1", AddressClass::Loopback),
        ("::a9fe:a9fe", AddressClass::Metadata),
        ("::a00:5", AddressClass::Private),
        ("2002:a00:5::", AddressClass::Private),
        ("2002:7f00:1::", AddressClass::Loopback),
        ("2002:a9fe:a9fe::", AddressClass::Metadata),
    ];
    cases.iter().try_for_each(|(text, class)| -> TestResult {
        assert_eq!(refused_class(text, &[])?, *class, "{text}");
        Ok(())
    })
}


#[test]
fn embedded_public_ipv4_passes_and_scope_is_honoured() -> TestResult {
    assert_eq!(checked_ip(&guard_address(ip("64:ff9b::5db8:d822")?, &[])?), ip("64:ff9b::5db8:d822")?);
    assert_eq!(checked_ip(&guard_address(ip("2002:5db8:d822::")?, &[])?), ip("2002:5db8:d822::")?);
    let scope = [net("64:ff9b::a00:0/120")?];
    assert_eq!(checked_ip(&guard_address(ip("64:ff9b::a00:5")?, &scope)?), ip("64:ff9b::a00:5")?);
    assert_eq!(refused_class("64:ff9b::a00:105", &scope)?, AddressClass::Private);
    assert_eq!(refused_class("64:ff9b::a9fe:a9fe", &[net("64:ff9b::/96")?])?, AddressClass::Metadata);
    Ok(())
}


#[test]
fn scope_can_allow_reserved() -> TestResult {
    assert_eq!(
        checked_ip(&guard_address(ip("100.64.0.1")?, &[net("100.64.0.0/16")?])?),
        ip("100.64.0.1")?
    );
    assert_eq!(refused_class("100.100.100.200", &[net("100.64.0.0/10")?])?, AddressClass::Metadata);
    Ok(())
}


#[test]
fn local_nat64_prefix_is_refused_whole_unless_scoped() -> TestResult {
    let texts = [
        "64:ff9b:1::a00:5",
        "64:ff9b:1:abcd:a:0:508:808",
        "64:ff9b:1:abcd:7f:0:108:808",
        "64:ff9b:1:ab0a:0:5:808:808",
        "64:ff9b:1:aba9:fe:a9fe:808:808",
        "64:ff9b:1:ab7f:0:1:808:808",
        "64:ff9b:1:0:0:0:808:808",
    ];
    texts.iter().try_for_each(|text| -> TestResult {
        assert_eq!(refused_class(text, &[])?, AddressClass::Reserved, "{text}");
        Ok(())
    })?;
    let scope = [net("64:ff9b:1::/48")?];
    assert_eq!(
        checked_ip(&guard_address(ip("64:ff9b:1:0:0:0:808:808")?, &scope)?),
        ip("64:ff9b:1::808:808")?
    );
    Ok(())
}


#[test]
fn benchmarking_range_is_reserved() -> TestResult {
    assert_eq!(refused_class("198.18.0.1", &[])?, AddressClass::Reserved);
    assert_eq!(refused_class("198.19.255.254", &[])?, AddressClass::Reserved);
    assert_eq!(checked_ip(&guard_address(ip("198.17.0.1")?, &[])?), ip("198.17.0.1")?);
    assert_eq!(checked_ip(&guard_address(ip("198.20.0.1")?, &[])?), ip("198.20.0.1")?);
    Ok(())
}


#[test]
fn metadata_at_the_nat64_local_embedded_position_is_never_scoped() -> TestResult {
    let scope = [net("64:ff9b:1::/48")?];
    assert_eq!(refused_class("64:ff9b:1::a9fe:a9fe", &scope)?, AddressClass::Metadata);
    assert_eq!(refused_class("64:ff9b:1:0:0:0:a9fe:a9fe", &[])?, AddressClass::Reserved);
    assert!(guard_address(ip("64:ff9b:1::808:808")?, &scope).is_ok());
    Ok(())
}


const NAT64_LOCAL_PREFIX: [u8; 6] = [0, 0x64, 0xff, 0x9b, 0, 1];


const METADATA_OCTETS: [u8; EMBEDDED_OCTETS] = [169, 254, 169, 254];


const EMBEDDED_OCTETS: usize = 4;


const POSITION_COUNT: usize = 4;


const ADDRESS_OCTETS: usize = 16;


const PREFIX_POSITIONS: usize = 6;


const POSITIONS: [[usize; EMBEDDED_OCTETS]; POSITION_COUNT] = [[6, 7, 9, 10], [7, 9, 10, 11], [9, 10, 11, 12], [12, 13, 14, 15]];


fn address_with_metadata_at(positions: &[usize; EMBEDDED_OCTETS]) -> Ipv6Addr {
    let mut octets = [0u8; ADDRESS_OCTETS];
    NAT64_LOCAL_PREFIX.iter().enumerate().for_each(|(index, value)| {
        octets.get_mut(index).into_iter().for_each(|slot| *slot = *value);
    });
    positions.iter().zip(METADATA_OCTETS).for_each(|(position, value)| {
        octets.get_mut(*position).into_iter().for_each(|slot| *slot = value);
    });
    Ipv6Addr::from(octets)
}


#[test]
fn metadata_at_every_rfc_6052_position_is_never_scoped() -> TestResult {
    let scope = [net("64:ff9b:1::/48")?];
    POSITIONS.iter().try_for_each(|positions| -> TestResult {
        let address = IpAddr::V6(address_with_metadata_at(positions));
        assert!(embedded_v4(address).contains(&Ipv4Addr::from(METADATA_OCTETS)), "{address}");
        assert_eq!(refused_class(&address.to_string(), &scope)?, AddressClass::Metadata, "{address}");
        Ok(())
    })?;
    assert_eq!(embedded_v4(ip("64:ff9b:1::")?).len(), PREFIX_POSITIONS);
    assert!(embedded_v4(ip("192.0.2.1")?).is_empty());
    Ok(())
}
