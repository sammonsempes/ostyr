use crate::error::{AddressClass, GuardError};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};


pub const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);


pub const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);


/// An address that passed the guard; the field is private so the only way to get one is `guard_address`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedAddr {
    address: IpAddr,
}


pub fn classify(address: IpAddr) -> Option<AddressClass> {
    let table = match address {
        IpAddr::V4(v4) => [
            (v4 == METADATA_V4, AddressClass::Metadata),
            (v4.is_loopback(), AddressClass::Loopback),
            (v4.is_private(), AddressClass::Private),
            (v4.is_link_local(), AddressClass::LinkLocal),
            (v4.is_multicast(), AddressClass::Multicast),
            (v4.is_unspecified(), AddressClass::Unspecified),
        ],
        IpAddr::V6(v6) => [
            (v6 == METADATA_V6, AddressClass::Metadata),
            (v6.is_loopback(), AddressClass::Loopback),
            (v6.is_unique_local(), AddressClass::UniqueLocal),
            (v6.is_unicast_link_local(), AddressClass::LinkLocal),
            (v6.is_multicast(), AddressClass::Multicast),
            (v6.is_unspecified(), AddressClass::Unspecified),
        ],
    };
    table.into_iter().find_map(|(matches, class)| matches.then_some(class))
}


/// Checks a resolved address (IPv4-mapped IPv6 unwrapped first); a metadata address is refused even when a scope entry covers it.
pub fn guard_address(address: IpAddr, scope: &[IpNet]) -> Result<CheckedAddr, GuardError> {
    let canonical = address.to_canonical();
    let verdict = match classify(canonical) {
        None => Ok(()),
        Some(AddressClass::Metadata) => Err(AddressClass::Metadata),
        Some(class) => scope.iter().any(|network| network.contains(&canonical)).then_some(()).ok_or(class),
    };
    verdict
        .map(|()| CheckedAddr { address: canonical })
        .map_err(|class| GuardError::Refused { address, class })
}


pub fn checked_ip(address: &CheckedAddr) -> IpAddr {
    address.address
}


/// The only input of a probe: connect to this socket address, never to a name.
pub fn probe_socket(address: CheckedAddr, port: u16) -> SocketAddr {
    SocketAddr::new(address.address, port)
}
