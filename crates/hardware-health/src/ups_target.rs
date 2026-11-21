//! Grammar of a `<ups>@<host>[:<port>]` upsc target: an ASCII allowlist, no implicit host, no IPv6, no host glibc would read as a number.

use crate::limits::{
    DEFAULT_UPS_PORT, IPV4_OCTETS, MAX_DNS_LABEL_BYTES, MAX_DNS_NAME_BYTES, MAX_OCTET_DIGITS, MAX_PORT_DIGITS, MAX_TARGET_BYTES, MAX_UPS_NAME_BYTES,
};
use crate::model::UpsTarget;


pub const MAX_OCTET: u16 = 255;


pub const RESERVED_UPS_NAME: &str = "default";


/// `[A-Za-z0-9][A-Za-z0-9_-]{0,31}` and not `default`.
pub fn is_ups_name(text: &str) -> bool {
    let first_ok = text.bytes().next().is_some_and(|byte| byte.is_ascii_alphanumeric());
    first_ok
        && text.len() <= MAX_UPS_NAME_BYTES
        && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        && !text.eq_ignore_ascii_case(RESERVED_UPS_NAME)
}


fn is_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= MAX_DNS_LABEL_BYTES
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}


/// A lowercase LDH name whose last label starts with a letter (so no numeric form such as `127.1` or `0x7f.1`), no trailing dot.
pub fn is_dns_name(text: &str) -> bool {
    let last_starts_with_letter = text
        .rsplit('.')
        .next()
        .and_then(|label| label.bytes().next())
        .is_some_and(|byte| byte.is_ascii_lowercase());
    last_starts_with_letter && text.len() <= MAX_DNS_NAME_BYTES && text.split('.').all(is_label)
}


fn is_octet(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_OCTET_DIGITS
        && text.bytes().all(|byte| byte.is_ascii_digit())
        && (text == "0" || !text.starts_with('0'))
        && text.parse::<u16>().is_ok_and(|value| value <= MAX_OCTET)
}


/// Four decimal octets, no leading zero.
pub fn is_ipv4(text: &str) -> bool {
    let octets: Vec<&str> = text.split('.').collect();
    octets.len() == IPV4_OCTETS && octets.iter().all(|octet| is_octet(octet))
}


/// `[1-9][0-9]{0,4}` and at most 65535.
pub fn is_port(text: &str) -> bool {
    !text.starts_with('0') && text.len() <= MAX_PORT_DIGITS && text.bytes().all(|byte| byte.is_ascii_digit()) && text.parse::<u16>().is_ok()
}


/// The checked target, or `None` when any part is refused.
pub fn parse_target(text: &str) -> Option<UpsTarget> {
    let (ups, host) = text.split_once('@')?;
    let (name, port) = host.split_once(':').map_or((host, None), |(name, port)| (name, Some(port)));
    let valid = text.len() <= MAX_TARGET_BYTES && is_ups_name(ups) && (is_ipv4(name) || is_dns_name(name)) && port.is_none_or(is_port);
    valid.then(|| UpsTarget {
        text: text.to_owned(),
        ups: ups.to_owned(),
        host: host.to_owned(),
    })
}


/// The UPS name folded and the host with the default port added: two targets with one key are the same.
pub fn target_key(target: &UpsTarget) -> (String, String) {
    let host = if target.host.contains(':') {
        target.host.clone()
    } else {
        format!("{}:{DEFAULT_UPS_PORT}", target.host)
    };
    (target.ups.to_ascii_lowercase(), host)
}
