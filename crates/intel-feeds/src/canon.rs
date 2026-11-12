use crate::error::CanonError;
use crate::limits::{MAX_URL_BYTES, MD5_HEX_LENGTH, MIN_IPV4_PREFIX, MIN_IPV6_PREFIX, SHA1_HEX_LENGTH, SHA256_HEX_LENGTH};
use crate::model::{Canonical, IocType};
use ipnet::IpNet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use url::Url;


/// The value decides between IPv4 and IPv6; an IPv4-mapped IPv6 address becomes IPv4.
pub fn canonical_address(text: &str) -> Result<Canonical, CanonError> {
    let address: IpAddr = text.parse().map_err(CanonError::Address)?;
    let (ioc_type, value) = match address {
        IpAddr::V4(version4) => (IocType::Ipv4, version4.to_string()),
        IpAddr::V6(version6) => version6
            .to_ipv4_mapped()
            .map_or_else(|| (IocType::Ipv6, version6.to_string()), |mapped| (IocType::Ipv4, mapped.to_string())),
    };
    Ok(Canonical { ioc_type, value })
}


/// An IPv4 network shorter than `/8` or an IPv6 one shorter than `/16` would match a large part of the internet.
pub fn is_too_broad(network: &IpNet) -> bool {
    match network {
        IpNet::V4(version4) => version4.prefix_len() < MIN_IPV4_PREFIX,
        IpNet::V6(version6) => version6.prefix_len() < MIN_IPV6_PREFIX,
    }
}


/// Host bits are cleared: `10.1.2.3/8` becomes `10.0.0.0/8`.
pub fn canonical_network(text: &str) -> Result<Canonical, CanonError> {
    let network: IpNet = text.parse().map_err(CanonError::Network)?;
    if is_too_broad(&network) {
        Err(CanonError::TooBroad)
    } else {
        Ok(Canonical {
            ioc_type: IocType::Cidr,
            value: network.trunc().to_string(),
        })
    }
}


/// A single label (a whole TLD) is too broad. Lowercase, no trailing dot, IDNA to punycode with STD3 rules; idna also enforces the DNS length limits.
pub fn canonical_domain(text: &str) -> Result<Canonical, CanonError> {
    let ascii = idna::domain_to_ascii_strict(text.trim_end_matches('.')).map_err(CanonError::Domain)?;
    if ascii.contains('.') {
        Ok(Canonical {
            ioc_type: IocType::Domain,
            value: ascii,
        })
    } else {
        Err(CanonError::TooBroad)
    }
}


/// Parsed by the `url` crate (host lowercased and punycoded, path normalised), fragment dropped.
pub fn canonical_url(text: &str) -> Result<Canonical, CanonError> {
    let mut parsed = Url::parse(text).map_err(CanonError::Url)?;
    parsed.set_fragment(None);
    if parsed.has_host() && parsed.as_str().len() <= MAX_URL_BYTES {
        Ok(Canonical {
            ioc_type: IocType::Url,
            value: parsed.into(),
        })
    } else {
        Err(CanonError::UrlShape)
    }
}


pub fn canonical_hash(ioc_type: IocType, expected: usize, text: &str) -> Result<Canonical, CanonError> {
    if text.len() == expected && text.chars().all(|character| character.is_ascii_hexdigit()) {
        Ok(Canonical {
            ioc_type,
            value: text.to_ascii_lowercase(),
        })
    } else {
        Err(CanonError::Hash { expected })
    }
}


pub fn canonicalise(declared: IocType, raw: &str) -> Result<Canonical, CanonError> {
    let text = raw.trim();
    match declared {
        IocType::Ipv4 | IocType::Ipv6 => canonical_address(text),
        IocType::Cidr => canonical_network(text),
        IocType::Domain => canonical_domain(text),
        IocType::Url => canonical_url(text),
        IocType::Md5 => canonical_hash(declared, MD5_HEX_LENGTH, text),
        IocType::Sha1 => canonical_hash(declared, SHA1_HEX_LENGTH, text),
        IocType::Sha256 => canonical_hash(declared, SHA256_HEX_LENGTH, text),
    }
}


pub fn hash_type_of_length(length: usize) -> IocType {
    match length {
        MD5_HEX_LENGTH => IocType::Md5,
        SHA1_HEX_LENGTH => IocType::Sha1,
        SHA256_HEX_LENGTH => IocType::Sha256,
        _ => IocType::Domain,
    }
}


/// Guesses the type of a value whose feed does not say: a URL, a network, an address, a hash by length, else a domain.
pub fn detect_type(raw: &str) -> IocType {
    let text = raw.trim();
    if text.contains("://") {
        IocType::Url
    } else if text.contains('/') {
        IocType::Cidr
    } else if text.parse::<Ipv4Addr>().is_ok() {
        IocType::Ipv4
    } else if text.parse::<Ipv6Addr>().is_ok() {
        IocType::Ipv6
    } else if text.chars().all(|character| character.is_ascii_hexdigit()) {
        hash_type_of_length(text.len())
    } else {
        IocType::Domain
    }
}


/// Type names used by feeds; `None` for anything else (`ip:port`, unknown), so the value is detected.
pub fn type_from_name(name: &str) -> Option<IocType> {
    match name.trim().to_ascii_lowercase().as_str() {
        "ipv4" | "ipv4-addr" => Some(IocType::Ipv4),
        "ipv6" | "ipv6-addr" => Some(IocType::Ipv6),
        "cidr" | "network" => Some(IocType::Cidr),
        "domain" | "domain-name" | "fqdn" | "hostname" => Some(IocType::Domain),
        "url" | "uri" => Some(IocType::Url),
        "md5" | "md5_hash" => Some(IocType::Md5),
        "sha1" | "sha-1" | "sha1_hash" => Some(IocType::Sha1),
        "sha256" | "sha-256" | "sha256_hash" => Some(IocType::Sha256),
        _ => None,
    }
}
