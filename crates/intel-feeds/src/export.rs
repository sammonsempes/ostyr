use crate::config::ExportPolicy;
use crate::model::{Ioc, IocType, Tlp};
use crate::types::IocIndex;
use serde::Serialize;
use sha1::{Digest, Sha1};
use std::collections::BTreeMap;
use std::io::{self, Write};
use time::{OffsetDateTime, UtcOffset};
use uuid::{Builder, Uuid};


pub const STIX_NAMESPACE: Uuid = Uuid::from_u128(0x6f1d_52a4_9b7e_4c3a_8d21_5e0b_c7a9_1f34);


pub const UUID_BYTES: usize = 16;


pub const SPEC_VERSION: &str = "2.1";


pub const REASON_TLP: &str = "tlp_above_ceiling";


pub const REASON_CONFIDENCE: &str = "confidence_below_minimum";


pub const REASON_TYPE: &str = "type_not_exported";


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Indicator {
    #[serde(rename = "type")]
    pub object_type: &'static str,
    pub spec_version: &'static str,
    pub id: String,
    #[serde(with = "time::serde::rfc3339")]
    pub created: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub modified: OffsetDateTime,
    pub pattern: String,
    pub pattern_type: &'static str,
    #[serde(with = "time::serde::rfc3339")]
    pub valid_from: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option", skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<OffsetDateTime>,
    pub confidence: u8,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    pub object_marking_refs: Vec<&'static str>,
}


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Bundle {
    #[serde(rename = "type")]
    pub object_type: &'static str,
    pub id: String,
    pub objects: Vec<Indicator>,
}


/// Exported count and, per reason, the IOCs the policy refused.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize)]
pub struct ExportSummary {
    pub exported: u64,
    pub refused: BTreeMap<&'static str, u64>,
}


pub fn type_label(ioc_type: IocType) -> &'static str {
    match ioc_type {
        IocType::Ipv4 => "ipv4",
        IocType::Ipv6 => "ipv6",
        IocType::Cidr => "cidr",
        IocType::Domain => "domain",
        IocType::Url => "url",
        IocType::Md5 => "md5",
        IocType::Sha1 => "sha1",
        IocType::Sha256 => "sha256",
    }
}


/// TLP 2.0 marking definition ids (OASIS common objects).
pub fn tlp_marking(tlp: Tlp) -> &'static str {
    match tlp {
        Tlp::Clear => "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
        Tlp::Green => "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
        Tlp::Amber => "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
        Tlp::AmberStrict => "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
        Tlp::Red => "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
    }
}


/// A STIX string literal is closed by an unescaped quote: backslash and quote are escaped, in that order.
pub fn escape_literal(value: &str) -> String {
    value.replace('\\', "\\\\").replace('\'', "\\'")
}


pub fn pattern_of(ioc_type: IocType, value: &str) -> String {
    let literal = escape_literal(value);
    match ioc_type {
        IocType::Ipv4 => format!("[ipv4-addr:value = '{literal}']"),
        IocType::Ipv6 => format!("[ipv6-addr:value = '{literal}']"),
        IocType::Cidr if value.contains(':') => format!("[ipv6-addr:value ISSUBSET '{literal}']"),
        IocType::Cidr => format!("[ipv4-addr:value ISSUBSET '{literal}']"),
        IocType::Domain => format!("[domain-name:value = '{literal}']"),
        IocType::Url => format!("[url:value = '{literal}']"),
        IocType::Md5 => format!("[file:hashes.'MD5' = '{literal}']"),
        IocType::Sha1 => format!("[file:hashes.'SHA-1' = '{literal}']"),
        IocType::Sha256 => format!("[file:hashes.'SHA-256' = '{literal}']"),
    }
}


/// UUIDv5 (RFC 9562): SHA-1 over the namespace bytes then the name, version and variant bits set by the builder.
pub fn uuid_v5(namespace: &Uuid, name: &str) -> Uuid {
    let digest = Sha1::new().chain_update(namespace.as_bytes()).chain_update(name.as_bytes()).finalize();
    let mut bytes = [0; UUID_BYTES];
    bytes.iter_mut().zip(digest.iter()).for_each(|(target, source)| *target = *source);
    Builder::from_sha1_bytes(bytes).into_uuid()
}


pub fn indicator_id(ioc_type: IocType, value: &str) -> String {
    format!("indicator--{}", uuid_v5(&STIX_NAMESPACE, &format!("{}:{value}", type_label(ioc_type))))
}


pub fn labels_of(ioc: &Ioc) -> Vec<String> {
    [
        ("malware", &ioc.tags.malware),
        ("actor", &ioc.tags.actor),
        ("campaign", &ioc.tags.campaign),
    ]
    .iter()
    .flat_map(|(kind, tags)| tags.iter().map(move |tag| format!("{kind}:{tag}")))
    .collect()
}


pub fn indicator_of(ioc: &Ioc) -> Indicator {
    Indicator {
        object_type: "indicator",
        spec_version: SPEC_VERSION,
        id: indicator_id(ioc.ioc_type, &ioc.value),
        created: ioc.first_seen.to_offset(UtcOffset::UTC),
        modified: ioc.last_seen.to_offset(UtcOffset::UTC),
        pattern: pattern_of(ioc.ioc_type, &ioc.value),
        pattern_type: "stix",
        valid_from: ioc.first_seen.to_offset(UtcOffset::UTC),
        valid_until: ioc.expires_at.map(|expiry| expiry.to_offset(UtcOffset::UTC)),
        confidence: ioc.confidence,
        labels: labels_of(ioc),
        object_marking_refs: vec![tlp_marking(ioc.tlp)],
    }
}


/// The first reason that applies: TLP ceiling, then minimum confidence, then the type list.
pub fn refusal(ioc: &Ioc, policy: &ExportPolicy) -> Option<&'static str> {
    if ioc.tlp > policy.max_tlp {
        Some(REASON_TLP)
    } else if ioc.confidence < policy.min_confidence {
        Some(REASON_CONFIDENCE)
    } else if policy.types.as_ref().is_some_and(|types| !types.contains(&ioc.ioc_type)) {
        Some(REASON_TYPE)
    } else {
        None
    }
}


/// Indicators sorted by id; the bundle id is a UUIDv5 over the sorted ids, so equal input gives equal bytes.
pub fn build_bundle(index: &IocIndex, policy: &ExportPolicy) -> (Bundle, ExportSummary) {
    let mut summary = ExportSummary::default();
    let mut objects: Vec<Indicator> = index
        .values()
        .filter(|ioc| {
            let reason = refusal(ioc, policy);
            reason.iter().for_each(|key| *summary.refused.entry(key).or_insert(0) += 1);
            reason.is_none()
        })
        .map(indicator_of)
        .collect();
    objects.sort_by(|left, right| left.id.cmp(&right.id));
    summary.exported = objects.len() as u64;
    let names: Vec<&str> = objects.iter().map(|object| object.id.as_str()).collect();
    let id = format!("bundle--{}", uuid_v5(&STIX_NAMESPACE, &names.join(",")));
    (
        Bundle {
            object_type: "bundle",
            id,
            objects,
        },
        summary,
    )
}


/// Writes one compact JSON bundle and a newline; the summary says what the policy kept out.
pub fn export_bundle(index: &IocIndex, policy: &ExportPolicy, out: &mut dyn Write) -> io::Result<ExportSummary> {
    let (bundle, summary) = build_bundle(index, policy);
    serde_json::to_writer(&mut *out, &bundle)?;
    writeln!(out)?;
    Ok(summary)
}
