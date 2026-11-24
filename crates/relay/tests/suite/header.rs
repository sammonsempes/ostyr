use crate::support::TestResult;
use relay::header::{as_ipv6, proxy_header};
use relay::model::PROXY_V2_SIGNATURE;
use std::net::{IpAddr, SocketAddr};


const IPV4_HEADER_BYTES: usize = 28;


const IPV6_HEADER_BYTES: usize = 52;


const TCP4_BLOCK: [u8; 16] = [0x21, 0x11, 0x00, 0x0C, 192, 0, 2, 1, 198, 51, 100, 7, 0x9C, 0x40, 0x01, 0xBB];


const TCP6_PREFIX: [u8; 4] = [0x21, 0x21, 0x00, 0x24];


const PORTS: [u8; 4] = [0x9C, 0x40, 0x01, 0xBB];


const FAMILY_OFFSET: usize = 13;


const TCP6_FAMILY: u8 = 0x21;


const SOURCE_START: usize = 16;


const SOURCE_END: usize = 32;


fn address(text: &str) -> Result<SocketAddr, std::net::AddrParseError> {
    text.parse()
}


#[test]
fn two_ipv4_addresses_give_a_28_byte_tcp4_header() -> TestResult {
    let header = proxy_header(address("192.0.2.1:40000")?, address("198.51.100.7:443")?);
    let expected = [PROXY_V2_SIGNATURE.to_vec(), TCP4_BLOCK.to_vec()].concat();
    assert_eq!(header.len(), IPV4_HEADER_BYTES);
    assert_eq!(header, expected);
    Ok(())
}


#[test]
fn mapped_addresses_are_folded_to_ipv4() -> TestResult {
    let header = proxy_header(address("[::ffff:192.0.2.1]:40000")?, address("[::ffff:198.51.100.7]:443")?);
    assert_eq!(header, proxy_header(address("192.0.2.1:40000")?, address("198.51.100.7:443")?));
    Ok(())
}


#[test]
fn an_ipv6_peer_gives_a_52_byte_tcp6_header_and_a_mapped_destination() -> TestResult {
    let header = proxy_header(address("[2001:db8::1]:40000")?, address("198.51.100.7:443")?);
    let source = "2001:db8::1".parse::<std::net::Ipv6Addr>()?.octets();
    let destination = "::ffff:198.51.100.7".parse::<std::net::Ipv6Addr>()?.octets();
    let expected = [
        PROXY_V2_SIGNATURE.to_vec(),
        TCP6_PREFIX.to_vec(),
        source.to_vec(),
        destination.to_vec(),
        PORTS.to_vec(),
    ]
    .concat();
    assert_eq!(header.len(), IPV6_HEADER_BYTES);
    assert_eq!(header, expected);
    Ok(())
}


#[test]
fn an_ipv4_peer_with_an_ipv6_destination_maps_the_peer() -> TestResult {
    let header = proxy_header(address("192.0.2.1:40000")?, address("[2001:db8::7]:443")?);
    assert_eq!(header.get(FAMILY_OFFSET), Some(&TCP6_FAMILY));
    assert_eq!(header.len(), IPV6_HEADER_BYTES);
    let mapped = as_ipv6("192.0.2.1".parse::<IpAddr>()?);
    assert_eq!(header.get(SOURCE_START..SOURCE_END), Some(mapped.octets().as_slice()));
    Ok(())
}
