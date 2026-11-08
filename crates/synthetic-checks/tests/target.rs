#[path = "common/types.rs"]
mod types;


use ipnet::IpNet;
use std::net::{IpAddr, SocketAddr};
use synthetic_checks::error::AddressClass;
use synthetic_checks::target::{checked_ip, guard_address, probe_socket};
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
