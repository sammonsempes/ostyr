use crate::model::{PROXY_V2_SIGNATURE, PROXY_V2_TCP4, PROXY_V2_TCP4_LENGTH, PROXY_V2_TCP6, PROXY_V2_TCP6_LENGTH, PROXY_V2_VERSION_COMMAND};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};


/// The PROXY v2 header of one accepted connection: both addresses canonical, IPv4 when both are, else both as IPv6; no TLV.
pub fn proxy_header(peer: SocketAddr, local: SocketAddr) -> Vec<u8> {
    let source = peer.ip().to_canonical();
    let destination = local.ip().to_canonical();
    let mut header = PROXY_V2_SIGNATURE.to_vec();
    header.push(PROXY_V2_VERSION_COMMAND);
    match (source, destination) {
        (IpAddr::V4(from), IpAddr::V4(to)) => {
            header.push(PROXY_V2_TCP4);
            header.extend_from_slice(&PROXY_V2_TCP4_LENGTH.to_be_bytes());
            header.extend_from_slice(&from.octets());
            header.extend_from_slice(&to.octets());
        }
        (from, to) => {
            header.push(PROXY_V2_TCP6);
            header.extend_from_slice(&PROXY_V2_TCP6_LENGTH.to_be_bytes());
            header.extend_from_slice(&as_ipv6(from).octets());
            header.extend_from_slice(&as_ipv6(to).octets());
        }
    }
    header.extend_from_slice(&peer.port().to_be_bytes());
    header.extend_from_slice(&local.port().to_be_bytes());
    header
}


pub fn as_ipv6(address: IpAddr) -> Ipv6Addr {
    match address {
        IpAddr::V4(four) => four.to_ipv6_mapped(),
        IpAddr::V6(six) => six,
    }
}
