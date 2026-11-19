use pg_fake::certs::{loopback, make_pki};
use rcgen::SanType;
use std::error::Error;
use std::net::IpAddr;


#[test]
fn make_pki_signs_a_server_certificate_for_an_address_or_a_name() -> Result<(), Box<dyn Error>> {
    assert_eq!(loopback(), "127.0.0.1".parse::<IpAddr>()?);
    let by_address = make_pki(SanType::IpAddress(loopback()))?;
    assert!(by_address.ca_pem.starts_with("-----BEGIN CERTIFICATE-----"));
    let by_name = make_pki(SanType::DnsName("localhost".try_into()?))?;
    assert_ne!(by_name.ca_pem, by_address.ca_pem);
    Ok(())
}
