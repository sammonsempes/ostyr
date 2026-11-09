use crate::model::ProxyOutcome;
use ipnet::IpNet;
use ppp::v2::{Addresses, Command, Header, PROTOCOL_PREFIX};
use std::io;
use std::net::IpAddr;
use tokio::io::{AsyncRead, AsyncReadExt};


pub const SIGNATURE_BYTES: usize = 12;


pub const TAIL_BYTES: usize = 4;


/// True when the socket peer is one of the trusted proxies (an IPv4-mapped address counts as its IPv4).
pub fn is_trusted(proxies: &[IpNet], peer: IpAddr) -> bool {
    let canonical = peer.to_canonical();
    proxies.iter().any(|proxy| proxy.contains(&canonical))
}


/// What a complete header says: the client for a PROXY command over IPv4 or IPv6, `Local` for a proxy health check, anything else malformed.
pub fn parse_header(bytes: &[u8]) -> ProxyOutcome {
    match Header::try_from(bytes) {
        Ok(header) if header.command == Command::Local => ProxyOutcome::Local,
        Ok(header) => match header.addresses {
            Addresses::IPv4(addresses) => ProxyOutcome::Client(IpAddr::V4(addresses.source_address)),
            Addresses::IPv6(addresses) => ProxyOutcome::Client(IpAddr::V6(addresses.source_address)),
            Addresses::Unspecified | Addresses::Unix(_) => ProxyOutcome::Malformed,
        },
        Err(_) => ProxyOutcome::Malformed,
    }
}


/// Reads one PROXY protocol v2 header, never more than `max_bytes` in all; the length is checked before the rest is read or buffered.
pub async fn read_header<Input: AsyncRead + Unpin>(stream: &mut Input, max_bytes: usize) -> io::Result<ProxyOutcome> {
    let mut signature = [u8::MIN; SIGNATURE_BYTES];
    let mut tail = [u8::MIN; TAIL_BYTES];
    stream.read_exact(&mut signature).await?;
    stream.read_exact(&mut tail).await?;
    let [version, family, high, low] = tail;
    let body_bytes = usize::from(u16::from_be_bytes([high, low]));
    if signature.as_slice() == PROTOCOL_PREFIX && SIGNATURE_BYTES + TAIL_BYTES + body_bytes <= max_bytes {
        let mut body = vec![u8::MIN; body_bytes];
        stream.read_exact(&mut body).await?;
        let whole = [signature.as_slice(), &[version, family, high, low], body.as_slice()].concat();
        Ok(parse_header(&whole))
    } else {
        Ok(ProxyOutcome::Malformed)
    }
}
