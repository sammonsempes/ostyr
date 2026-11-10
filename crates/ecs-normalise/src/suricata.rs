//! Suricata EVE JSON lines (alert, flow, dns, http, tls) mapped to ECS (spec section 14, NDR).

use crate::convert::Outcome;
use crate::error::NormaliseError;
use crate::types::Label;
use core_export::ecs::{
    blank_event, DnsFields, DnsQuestion, EcsEvent, EndpointFields, EventFields, HostFields, HttpBodyFields, HttpFields, HttpRequestFields,
    HttpResponseFields, JaHash, NetworkFields, RuleFields, TlsClientFields, TlsFields, TlsServerFields, UrlFields, UserAgentFields,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use serde_json::{from_str, Value};
use std::net::IpAddr;
use time::OffsetDateTime;
use tracing::warn;


pub const MODULE: &str = "suricata";


pub const MAX_FIELD_CHARS: usize = 256;


pub const MAX_ANSWERS: usize = 16;


pub const BAD_LABEL_PREFIX: &str = "suricata_bad_";


pub const REPLACEMENT: char = '\u{FFFD}';


pub const OMITTED_ANSWERS_LABEL: &str = "dns_answers_omitted";


time::serde::format_description!(
    eve_time,
    OffsetDateTime,
    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond][offset_hour sign:mandatory][offset_minute]"
);


#[derive(Debug, Default, Deserialize)]
pub struct Alert {
    pub action: Option<String>,
    pub signature_id: Option<Value>,
    pub signature: Option<String>,
    pub category: Option<String>,
    pub severity: Option<Value>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Flow {
    pub pkts_toserver: Option<Value>,
    pub pkts_toclient: Option<Value>,
    pub bytes_toserver: Option<Value>,
    pub bytes_toclient: Option<Value>,
    #[serde(default, with = "eve_time::option")]
    pub start: Option<OffsetDateTime>,
    #[serde(default, with = "eve_time::option")]
    pub end: Option<OffsetDateTime>,
}


#[derive(Debug, Default, Deserialize)]
pub struct DnsQuery {
    pub rrname: Option<String>,
    pub rrtype: Option<String>,
}


#[derive(Debug, Default, Deserialize)]
pub struct DnsAnswer {
    pub rdata: Option<String>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Dns {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub rrname: Option<String>,
    pub rrtype: Option<String>,
    pub rcode: Option<String>,
    pub rdata: Option<String>,
    #[serde(default)]
    pub queries: Vec<DnsQuery>,
    #[serde(default)]
    pub answers: Vec<DnsAnswer>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Http {
    pub hostname: Option<String>,
    pub url: Option<String>,
    pub http_user_agent: Option<String>,
    pub http_method: Option<String>,
    pub protocol: Option<String>,
    pub status: Option<Value>,
    pub length: Option<Value>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Ja {
    pub hash: Option<String>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Tls {
    pub version: Option<String>,
    pub sni: Option<String>,
    pub subject: Option<String>,
    pub issuerdn: Option<String>,
    pub notafter: Option<String>,
    pub ja3: Option<Ja>,
    pub ja3s: Option<Ja>,
}


/// The top-level EVE fields the mapping reads; the object of the line's own type is parsed apart, every other object is ignored.
#[derive(Debug, Deserialize)]
pub struct Eve {
    #[serde(with = "eve_time")]
    pub timestamp: OffsetDateTime,
    pub event_type: String,
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub proto: Option<String>,
    pub app_proto: Option<String>,
    pub community_id: Option<String>,
    pub flow_id: Option<u64>,
    pub in_iface: Option<String>,
    pub host: Option<String>,
}


/// A copy of the detection store's cut: the kept prefix, then `[cut, N chars]`.
pub fn cut_text(text: &str, max: usize) -> String {
    let length = text.chars().count();
    if length <= max {
        text.to_owned()
    } else {
        format!("{}[cut, {length} chars]", text.chars().take(max).collect::<String>())
    }
}


/// Control, bidirectional, zero-width and line-separator characters.
pub fn is_unsafe(found: char) -> bool {
    found.is_control()
        || matches!(found, '\u{200B}'..='\u{200D}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{FEFF}' | '\u{2028}' | '\u{2029}')
}


/// Peer text made safe to store: control characters replaced, then cut at `MAX_FIELD_CHARS`.
pub fn clean(text: &str) -> String {
    let printable: String = text.chars().map(|found| if is_unsafe(found) { REPLACEMENT } else { found }).collect();
    cut_text(&printable, MAX_FIELD_CHARS)
}


fn clean_opt(text: Option<&String>) -> Option<String> {
    text.filter(|found| !found.is_empty()).map(|found| clean(found))
}


fn non_empty<Group: Default + PartialEq>(group: Group) -> Option<Group> {
    Some(group).filter(|found| *found != Group::default())
}


fn endpoint(ip: Option<IpAddr>, port: Option<u16>, bytes: Option<u64>, packets: Option<u64>) -> Option<EndpointFields> {
    non_empty(EndpointFields {
        ip: ip.map(|address| address.to_string()),
        port,
        domain: None,
        bytes,
        packets,
    })
}


fn base_event(eve: &Eve, types: &[&str]) -> EcsEvent {
    let labels = [
        eve.flow_id.map(|flow_id| ("flow_id".to_string(), flow_id.to_string())),
        clean_opt(eve.in_iface.as_ref()).map(|name| ("in_iface".to_string(), name)),
    ];
    EcsEvent {
        event: EventFields {
            kind: Some("event".to_string()),
            category: vec!["network".to_string()],
            types: types.iter().map(|found| (*found).to_string()).collect(),
            dataset: Some(format!("{MODULE}.{}", eve.event_type)),
            module: Some(MODULE.to_string()),
            ..EventFields::default()
        },
        host: clean_opt(eve.host.as_ref()).map(|name| HostFields {
            name: Some(name),
            ..HostFields::default()
        }),
        source: endpoint(eve.src_ip, eve.src_port, None, None),
        destination: endpoint(eve.dest_ip, eve.dest_port, None, None),
        network: non_empty(NetworkFields {
            transport: clean_opt(eve.proto.as_ref()).map(|proto| proto.to_lowercase()),
            direction: None,
            protocol: clean_opt(eve.app_proto.as_ref()),
            community_id: clean_opt(eve.community_id.as_ref()),
        }),
        labels: labels.into_iter().flatten().collect(),
        ..blank_event(eve.timestamp)
    }
}


fn checked<Number: TryFrom<u64>>(field: &str, raw: Option<&Value>) -> (Option<Number>, Option<Label>) {
    match raw.map(|found| found.as_u64().and_then(|number| Number::try_from(number).ok()).ok_or(found)) {
        None => (None, None),
        Some(Ok(number)) => (Some(number), None),
        Some(Err(found)) => {
            let label = (format!("{BAD_LABEL_PREFIX}{field}"), clean(&found.to_string()));
            warn!(field, "a number out of range is kept as a label");
            (None, Some(label))
        }
    }
}


fn with_labels(event: EcsEvent, bad: impl IntoIterator<Item = Option<Label>>) -> EcsEvent {
    EcsEvent {
        labels: event.labels.clone().into_iter().chain(bad.into_iter().flatten()).collect(),
        ..event
    }
}


fn alert_event(alert: &Alert, base: EcsEvent) -> EcsEvent {
    let (id, bad_id): (Option<u64>, _) = checked("alert_signature_id", alert.signature_id.as_ref());
    let (severity, bad_severity) = checked("alert_severity", alert.severity.as_ref());
    with_labels(
        EcsEvent {
            event: EventFields {
                kind: Some("alert".to_string()),
                action: clean_opt(alert.action.as_ref()),
                severity,
                ..base.event.clone()
            },
            rule: non_empty(RuleFields {
                id: id.map(|found| found.to_string()),
                name: clean_opt(alert.signature.as_ref()),
                category: clean_opt(alert.category.as_ref()),
            }),
            ..base
        },
        [bad_id, bad_severity],
    )
}


fn flow_event(eve: &Eve, flow: &Flow, base: EcsEvent) -> EcsEvent {
    let (packets_out, bad_packets_out) = checked("flow_pkts_toserver", flow.pkts_toserver.as_ref());
    let (packets_in, bad_packets_in) = checked("flow_pkts_toclient", flow.pkts_toclient.as_ref());
    let (bytes_out, bad_bytes_out) = checked("flow_bytes_toserver", flow.bytes_toserver.as_ref());
    let (bytes_in, bad_bytes_in) = checked("flow_bytes_toclient", flow.bytes_toclient.as_ref());
    with_labels(
        EcsEvent {
            event: EventFields {
                start: flow.start,
                end: flow.end,
                ..base.event.clone()
            },
            source: endpoint(eve.src_ip, eve.src_port, bytes_out, packets_out),
            destination: endpoint(eve.dest_ip, eve.dest_port, bytes_in, packets_in),
            ..base
        },
        [bad_packets_out, bad_packets_in, bad_bytes_out, bad_bytes_in],
    )
}


fn dns_event(dns: &Dns, base: EcsEvent) -> EcsEvent {
    let query = dns.queries.first();
    let omitted = dns.answers.len().saturating_sub(MAX_ANSWERS);
    let resolved_ip: Vec<String> = dns
        .rdata
        .iter()
        .chain(dns.answers.iter().take(MAX_ANSWERS).filter_map(|answer| answer.rdata.as_ref()))
        .filter_map(|rdata| rdata.parse::<IpAddr>().ok())
        .map(|address| address.to_string())
        .collect();
    let omitted_label = Some(omitted)
        .filter(|count| *count > 0)
        .map(|count| (OMITTED_ANSWERS_LABEL.to_string(), count.to_string()));
    EcsEvent {
        dns: Some(DnsFields {
            question: DnsQuestion {
                name: clean_opt(dns.rrname.as_ref().or(query.and_then(|found| found.rrname.as_ref()))),
                kind: clean_opt(dns.rrtype.as_ref().or(query.and_then(|found| found.rrtype.as_ref()))),
            },
            kind: clean_opt(dns.kind.as_ref()),
            response_code: clean_opt(dns.rcode.as_ref()),
            resolved_ip,
        }),
        labels: base.labels.clone().into_iter().chain(omitted_label).collect(),
        ..base
    }
}


fn http_event(http: &Http, base: EcsEvent) -> EcsEvent {
    let url = clean_opt(http.url.as_ref());
    let (status, bad_status) = checked("http_status", http.status.as_ref());
    let (length, bad_length) = checked("http_length", http.length.as_ref());
    with_labels(
        EcsEvent {
            url: non_empty(UrlFields {
                domain: clean_opt(http.hostname.as_ref()),
                path: url
                    .as_deref()
                    .map(|found| found.split_once('?').map_or(found, |(path, _query)| path).to_string()),
                original: url,
            }),
            http: non_empty(HttpFields {
                version: clean_opt(http.protocol.as_ref()),
                request: non_empty(HttpRequestFields {
                    method: clean_opt(http.http_method.as_ref()),
                }),
                response: non_empty(HttpResponseFields {
                    status_code: status,
                    body: non_empty(HttpBodyFields { bytes: length }),
                }),
            }),
            user_agent: non_empty(UserAgentFields {
                original: clean_opt(http.http_user_agent.as_ref()),
            }),
            ..base
        },
        [bad_status, bad_length],
    )
}


fn ja_hash(ja: Option<&Ja>) -> Option<JaHash> {
    ja.and_then(|found| {
        non_empty(JaHash {
            hash: clean_opt(found.hash.as_ref()),
        })
    })
}


fn tls_event(tls: &Tls, base: EcsEvent) -> EcsEvent {
    EcsEvent {
        tls: non_empty(TlsFields {
            version: clean_opt(tls.version.as_ref()),
            client: non_empty(TlsClientFields {
                server_name: clean_opt(tls.sni.as_ref()),
                ja3: ja_hash(tls.ja3.as_ref()),
            }),
            server: non_empty(TlsServerFields {
                subject: clean_opt(tls.subject.as_ref()),
                issuer: clean_opt(tls.issuerdn.as_ref()),
                not_after: clean_opt(tls.notafter.as_ref()),
                ja3s: ja_hash(tls.ja3s.as_ref()),
            }),
        }),
        ..base
    }
}


/// The object of the line's own event type, parsed strictly: `MissingField` when absent, `Schema` when of the wrong shape.
fn own_object<Object: DeserializeOwned>(value: &Value, kind: &'static str) -> Result<Object, NormaliseError> {
    let object = value.get(kind).ok_or(NormaliseError::MissingField(kind))?;
    Object::deserialize(object).map_err(NormaliseError::Schema)
}


fn wrap(mapped: EcsEvent) -> Outcome {
    Outcome::Event(Box::new(mapped))
}


/// Maps one EVE line to an ECS event; an event type outside the five mapped ones is `Unknown("suricata:<type>")`.
pub fn convert_eve(eve: &Eve, value: &Value) -> Result<Outcome, NormaliseError> {
    match eve.event_type.as_str() {
        "alert" => own_object(value, "alert").map(|alert| wrap(alert_event(&alert, base_event(eve, &[])))),
        "flow" => own_object(value, "flow").map(|flow| wrap(flow_event(eve, &flow, base_event(eve, &["connection", "end"])))),
        "dns" => own_object(value, "dns").map(|dns| wrap(dns_event(&dns, base_event(eve, &["protocol"])))),
        "http" => own_object(value, "http").map(|http| wrap(http_event(&http, base_event(eve, &["protocol"])))),
        "tls" => own_object(value, "tls").map(|tls| wrap(tls_event(&tls, base_event(eve, &["protocol"])))),
        other => Ok(Outcome::Unknown(format!("{MODULE}:{}", clean(other)))),
    }
}


/// Parses one EVE line (an out-of-range peer number becomes a `suricata_bad_<field>` label): `Syntax` is invalid JSON, `Schema` is valid JSON of the wrong shape (a bad address, text type or timestamp included).
pub fn parse_eve(text: &str) -> Result<Outcome, NormaliseError> {
    let value: Value = from_str(text).map_err(NormaliseError::Syntax)?;
    let eve = Eve::deserialize(&value).map_err(NormaliseError::Schema)?;
    convert_eve(&eve, &value)
}
