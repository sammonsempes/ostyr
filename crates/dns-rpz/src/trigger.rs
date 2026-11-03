use crate::limits::MIN_ZERO_RUN;
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use std::cmp::Ordering;
use std::net::{AddrParseError, IpAddr, Ipv6Addr};


pub const IP_TRIGGER_SUFFIX: &str = "rpz-ip";


pub const ZERO_RUN_LABEL: &str = "zz";


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Run {
    pub start: usize,
    pub len: usize,
}


/// A CIDR or a bare address (a host network); host bits are cleared.
pub fn parse_net(value: &str) -> Result<IpNet, AddrParseError> {
    value
        .parse::<IpNet>()
        .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
        .map(|net| net.trunc())
}


pub fn ipv4_trigger(net: Ipv4Net) -> String {
    let octets = net.network().octets().iter().rev().map(u8::to_string).collect::<Vec<_>>().join(".");
    format!("{}.{octets}.{IP_TRIGGER_SUFFIX}", net.prefix_len())
}


/// The first longest run of zero segments.
pub fn longest_zero_run(segments: &[u16]) -> Run {
    let empty = Run { start: 0, len: 0 };
    let (best, _) = segments.iter().enumerate().fold((empty, empty), |(best, current), (index, segment)| {
        let extended = if *segment == 0 {
            Run {
                start: if current.len == 0 { index } else { current.start },
                len: current.len + 1,
            }
        } else {
            empty
        };
        (if extended.len > best.len { extended } else { best }, extended)
    });
    best
}


/// Reversed 16-bit fields joined by dots, the longest zero run (two fields or more) replaced by `zz`.
pub fn reversed_fields(address: Ipv6Addr) -> String {
    let mut segments = address.segments();
    segments.reverse();
    let run = longest_zero_run(&segments);
    let start = if run.len >= MIN_ZERO_RUN { run.start } else { segments.len() };
    segments
        .iter()
        .enumerate()
        .filter_map(|(index, segment)| match index.cmp(&start) {
            Ordering::Less => Some(format!("{segment:x}")),
            Ordering::Equal => Some(ZERO_RUN_LABEL.to_owned()),
            Ordering::Greater if index < start + run.len => None,
            Ordering::Greater => Some(format!("{segment:x}")),
        })
        .collect::<Vec<_>>()
        .join(".")
}


pub fn ipv6_trigger(net: Ipv6Net) -> String {
    format!("{}.{}.{IP_TRIGGER_SUFFIX}", net.prefix_len(), reversed_fields(net.network()))
}


/// `rpz-ip` owner name; a prefix of length 0 has none.
pub fn net_trigger(net: IpNet) -> Option<String> {
    match net {
        _ if net.prefix_len() == 0 => None,
        IpNet::V4(v4) => Some(ipv4_trigger(v4)),
        IpNet::V6(v6) => Some(ipv6_trigger(v6)),
    }
}
