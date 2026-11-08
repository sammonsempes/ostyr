use crate::error::{AddressClass, GuardError};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};


pub const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);


pub const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);


pub const METADATA_V4_EXTRA: [Ipv4Addr; 3] = [
    Ipv4Addr::new(100, 100, 100, 200),
    Ipv4Addr::new(192, 0, 0, 192),
    Ipv4Addr::new(168, 63, 129, 16),
];


pub const RESERVED_V4: [Ipv4Net; 4] = [
    Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10),
    Ipv4Net::new_assert(Ipv4Addr::new(0, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(240, 0, 0, 0), 4),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 0, 0, 0), 24),
];


pub const BROADCAST_V4: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);


pub const SITE_LOCAL_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10);


pub const NAT64_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96);


pub const NAT64_LOCAL_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48);


pub const SIX_TO_FOUR_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x2002, 0, 0, 0, 0, 0, 0, 0), 16);


pub const COMPATIBLE_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0), 96);


/// An address that passed the guard; the field is private so the only way to get one is `guard_address`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CheckedAddr {
    address: IpAddr,
}


pub fn classify(address: IpAddr) -> Option<AddressClass> {
    let table = match address {
        IpAddr::V4(v4) => [
            (v4 == METADATA_V4 || METADATA_V4_EXTRA.contains(&v4), AddressClass::Metadata),
            (v4.is_loopback(), AddressClass::Loopback),
            (v4.is_private(), AddressClass::Private),
            (v4.is_link_local(), AddressClass::LinkLocal),
            (v4.is_multicast(), AddressClass::Multicast),
            (v4.is_unspecified(), AddressClass::Unspecified),
            (
                v4 == BROADCAST_V4 || RESERVED_V4.iter().any(|network| network.contains(&v4)),
                AddressClass::Reserved,
            ),
        ],
        IpAddr::V6(v6) => [
            (v6 == METADATA_V6, AddressClass::Metadata),
            (v6.is_loopback(), AddressClass::Loopback),
            (v6.is_unique_local(), AddressClass::UniqueLocal),
            (v6.is_unicast_link_local(), AddressClass::LinkLocal),
            (v6.is_multicast(), AddressClass::Multicast),
            (v6.is_unspecified(), AddressClass::Unspecified),
            (SITE_LOCAL_V6.contains(&v6), AddressClass::Reserved),
        ],
    };
    table.into_iter().find_map(|(matches, class)| matches.then_some(class))
}


/// IPv4 addresses embedded in a NAT64, 6to4 or IPv4-compatible IPv6 address (every layout that could apply).
pub fn embedded_v4(address: IpAddr) -> Vec<Ipv4Addr> {
    match address {
        IpAddr::V4(_) => Vec::new(),
        IpAddr::V6(v6) => {
            let [_, _, o2, o3, o4, o5, _, _, _, _, _, _, o12, o13, o14, o15] = v6.octets();
            let [_, _, _, _, _, _, p6, p7, _, p9, p10, ..] = v6.octets();
            let last_32 = Ipv4Addr::new(o12, o13, o14, o15);
            let prefix_48 = Ipv4Addr::new(p6, p7, p9, p10);
            let six_to_four = Ipv4Addr::new(o2, o3, o4, o5);
            [
                (NAT64_V6.contains(&v6) || COMPATIBLE_V6.contains(&v6), vec![last_32]),
                (NAT64_LOCAL_V6.contains(&v6), vec![last_32, prefix_48]),
                (SIX_TO_FOUR_V6.contains(&v6), vec![six_to_four]),
            ]
            .into_iter()
            .filter_map(|(applies, found)| applies.then_some(found))
            .flatten()
            .collect()
        }
    }
}


fn check_candidate(candidate: IpAddr, canonical: IpAddr, scope: &[IpNet]) -> Result<(), AddressClass> {
    match classify(candidate) {
        None => Ok(()),
        Some(AddressClass::Metadata) => Err(AddressClass::Metadata),
        Some(class) => scope
            .iter()
            .any(|network| network.contains(&candidate) || network.contains(&canonical))
            .then_some(())
            .ok_or(class),
    }
}


/// Checks a resolved address (IPv4-mapped unwrapped, embedded IPv4 checked too); a metadata address is refused even when a scope entry covers it.
pub fn guard_address(address: IpAddr, scope: &[IpNet]) -> Result<CheckedAddr, GuardError> {
    let canonical = address.to_canonical();
    let embedded = embedded_v4(canonical);
    let verdict = std::iter::once(canonical)
        .chain(embedded.into_iter().map(IpAddr::V4))
        .try_for_each(|candidate| check_candidate(candidate, canonical, scope));
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
