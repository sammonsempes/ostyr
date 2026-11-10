use crate::error::{AddressClass, GuardError};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};


pub const METADATA_V4: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);


pub const METADATA_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);


pub const METADATA_V4_EXTRA: [Ipv4Addr; 4] = [
    Ipv4Addr::new(100, 100, 100, 200),
    Ipv4Addr::new(192, 0, 0, 192),
    Ipv4Addr::new(168, 63, 129, 16),
    Ipv4Addr::new(169, 254, 170, 2),
];


pub const RESERVED_V4: [Ipv4Net; 5] = [
    Ipv4Net::new_assert(Ipv4Addr::new(100, 64, 0, 0), 10),
    Ipv4Net::new_assert(Ipv4Addr::new(0, 0, 0, 0), 8),
    Ipv4Net::new_assert(Ipv4Addr::new(240, 0, 0, 0), 4),
    Ipv4Net::new_assert(Ipv4Addr::new(192, 0, 0, 0), 24),
    Ipv4Net::new_assert(Ipv4Addr::new(198, 18, 0, 0), 15),
];


pub const BROADCAST_V4: Ipv4Addr = Ipv4Addr::new(255, 255, 255, 255);


pub const SITE_LOCAL_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0xfec0, 0, 0, 0, 0, 0, 0, 0), 10);


pub const NAT64_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 0, 0, 0, 0, 0, 0), 96);


pub const NAT64_LOCAL_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x64, 0xff9b, 1, 0, 0, 0, 0, 0), 48);


pub const TEREDO_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0x2001, 0, 0, 0, 0, 0, 0, 0), 32);


pub const SIIT_V6: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0, 0, 0, 0, 0xffff, 0, 0, 0), 96);


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
            (
                SITE_LOCAL_V6.contains(&v6) || NAT64_LOCAL_V6.contains(&v6) || TEREDO_V6.contains(&v6),
                AddressClass::Reserved,
            ),
        ],
    };
    table.into_iter().find_map(|(matches, class)| matches.then_some(class))
}


pub const BITS_PER_OCTET: u8 = 8;


pub const RFC6052_U_OCTET: usize = 8;


pub const V4_OCTETS: usize = 4;


pub const ADDRESS_OCTETS: usize = 16;


pub const ISATAP_PREFIXES: [[u8; 2]; 2] = [[0, 0], [2, 0]];


pub const ISATAP_MARKER: [u8; 2] = [0x5e, 0xfe];


/// The IPv4 address of an RFC 6052 embedding for a prefix length (32, 40, 48, 56, 64 or 96): the four octets after the prefix, octet 8 skipped.
pub fn rfc6052_v4(octets: [u8; ADDRESS_OCTETS], prefix_len: u8) -> Option<Ipv4Addr> {
    let found: Vec<u8> = (usize::from(prefix_len / BITS_PER_OCTET)..)
        .filter(|index| *index != RFC6052_U_OCTET)
        .take(V4_OCTETS)
        .filter_map(|index| octets.get(index).copied())
        .collect();
    <[u8; V4_OCTETS]>::try_from(found).ok().map(Ipv4Addr::from)
}


/// `embedded_v4_nat64` without a declared NAT64 prefix.
pub fn embedded_v4(address: IpAddr) -> Vec<Ipv4Addr> {
    embedded_v4_nat64(address, None)
}


/// IPv4 addresses embedded in a NAT64 (64:ff9b::/96, a declared site prefix at its RFC 6052 positions, or any address whose bits 64 to 95 are zero and whose last 32 bits are not a bare low 16-bit host number), SIIT, 6to4, Teredo (server and obfuscated client), ISATAP or IPv4-compatible IPv6 address; 64:ff9b:1::/48 is refused whole by `classify`, and every RFC 6052 position is checked too so metadata there is never scoped.
pub fn embedded_v4_nat64(address: IpAddr, nat64: Option<Ipv6Net>) -> Vec<Ipv4Addr> {
    match address {
        IpAddr::V4(_) => Vec::new(),
        IpAddr::V6(v6) => {
            let octets = v6.octets();
            let [_, _, o2, o3, o4, o5, o6, o7, o8, o9, o10, o11, o12, o13, o14, o15] = octets;
            let teredo_client = Ipv4Addr::new(!o12, !o13, !o14, !o15);
            let low_host_number = o12 == 0 && o13 == 0 && (o14 | o15) != 0;
            let rfc6052_96 = (o8 | o9 | o10 | o11) == 0 && !low_host_number && !NAT64_LOCAL_V6.contains(&v6) && !SIX_TO_FOUR_V6.contains(&v6);
            let last_32 = Ipv4Addr::new(o12, o13, o14, o15);
            let six_to_four = Ipv4Addr::new(o2, o3, o4, o5);
            let isatap = ISATAP_PREFIXES.contains(&[o8, o9]) && [o10, o11] == ISATAP_MARKER;
            let declared: Vec<Ipv4Addr> = nat64
                .into_iter()
                .filter(|prefix| prefix.contains(&v6))
                .filter_map(|prefix| rfc6052_v4(octets, prefix.prefix_len()))
                .collect();
            [
                (
                    NAT64_V6.contains(&v6) || COMPATIBLE_V6.contains(&v6) || SIIT_V6.contains(&v6) || isatap,
                    vec![last_32],
                ),
                (TEREDO_V6.contains(&v6), vec![Ipv4Addr::new(o4, o5, o6, o7), teredo_client]),
                (
                    NAT64_LOCAL_V6.contains(&v6),
                    vec![
                        Ipv4Addr::new(o4, o5, o6, o7),
                        Ipv4Addr::new(o5, o6, o7, o9),
                        Ipv4Addr::new(o6, o7, o9, o10),
                        Ipv4Addr::new(o7, o9, o10, o11),
                        Ipv4Addr::new(o9, o10, o11, o12),
                        last_32,
                    ],
                ),
                (SIX_TO_FOUR_V6.contains(&v6), vec![six_to_four]),
                (rfc6052_96, vec![last_32]),
                (true, declared),
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
    guard_address_nat64(address, scope, None)
}


/// `guard_address` with the site's declared NAT64 prefix.
pub fn guard_address_nat64(address: IpAddr, scope: &[IpNet], nat64: Option<Ipv6Net>) -> Result<CheckedAddr, GuardError> {
    let canonical = address.to_canonical();
    let embedded = embedded_v4_nat64(canonical, nat64);
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
