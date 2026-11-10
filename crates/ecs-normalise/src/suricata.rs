//! Suricata EVE JSON lines (alert, flow, dns, http, tls) mapped to ECS (spec section 14, NDR).

use crate::convert::Outcome;
use crate::error::NormaliseError;
use core_export::ecs::{
    blank_event, DnsFields, DnsQuestion, EcsEvent, EndpointFields, EventFields, HostFields, HttpBodyFields, HttpFields, HttpRequestFields,
    HttpResponseFields, JaHash, NetworkFields, RuleFields, TlsClientFields, TlsFields, TlsServerFields, UrlFields, UserAgentFields,
};
use serde::Deserialize;
use serde_json::{from_str, from_value, Value};
use std::net::IpAddr;
use time::OffsetDateTime;


pub const MODULE: &str = "suricata";


pub const MAX_FIELD_CHARS: usize = 256;


pub const MAX_ANSWERS: usize = 16;


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
    pub signature_id: Option<u64>,
    pub signature: Option<String>,
    pub category: Option<String>,
    pub severity: Option<u32>,
}


#[derive(Debug, Default, Deserialize)]
pub struct Flow {
    pub pkts_toserver: Option<u64>,
    pub pkts_toclient: Option<u64>,
    pub bytes_toserver: Option<u64>,
    pub bytes_toclient: Option<u64>,
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
    pub status: Option<u16>,
    pub length: Option<u64>,
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


/// The EVE fields the mapping reads; anything else on the line is ignored.
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
    pub alert: Option<Alert>,
    pub flow: Option<Flow>,
    pub dns: Option<Dns>,
    pub http: Option<Http>,
    pub tls: Option<Tls>,
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


/// Peer text made safe to store: control characters replaced, then cut at `MAX_FIELD_CHARS`.
pub fn clean(text: &str) -> String {
    let printable: String = text.chars().map(|found| if found.is_control() { REPLACEMENT } else { found }).collect();
    cut_text(&printable, MAX_FIELD_CHARS)
}


fn clean_opt(text: Option<&String>) -> Option<String> {
    text.map(|found| clean(found))
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
        eve.in_iface.as_ref().map(|name| ("in_iface".to_string(), clean(name))),
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
        host: eve.host.as_ref().map(|name| HostFields {
            name: Some(clean(name)),
            ..HostFields::default()
        }),
        source: endpoint(eve.src_ip, eve.src_port, None, None),
        destination: endpoint(eve.dest_ip, eve.dest_port, None, None),
        network: non_empty(NetworkFields {
            transport: eve.proto.as_ref().map(|proto| clean(&proto.to_lowercase())),
            direction: None,
            protocol: clean_opt(eve.app_proto.as_ref()),
            community_id: clean_opt(eve.community_id.as_ref()),
        }),
        labels: labels.into_iter().flatten().collect(),
        ..blank_event(eve.timestamp)
    }
}


fn alert_event(eve: &Eve, base: EcsEvent) -> Result<EcsEvent, NormaliseError> {
    let alert = eve.alert.as_ref().ok_or(NormaliseError::MissingField("alert"))?;
    Ok(EcsEvent {
        event: EventFields {
            kind: Some("alert".to_string()),
            action: clean_opt(alert.action.as_ref()),
            severity: alert.severity,
            ..base.event.clone()
        },
        rule: non_empty(RuleFields {
            id: alert.signature_id.map(|id| id.to_string()),
            name: clean_opt(alert.signature.as_ref()),
            category: clean_opt(alert.category.as_ref()),
        }),
        ..base
    })
}


fn flow_event(eve: &Eve, base: EcsEvent) -> Result<EcsEvent, NormaliseError> {
    let flow = eve.flow.as_ref().ok_or(NormaliseError::MissingField("flow"))?;
    Ok(EcsEvent {
        event: EventFields {
            start: flow.start,
            end: flow.end,
            ..base.event.clone()
        },
        source: endpoint(eve.src_ip, eve.src_port, flow.bytes_toserver, flow.pkts_toserver),
        destination: endpoint(eve.dest_ip, eve.dest_port, flow.bytes_toclient, flow.pkts_toclient),
        ..base
    })
}


fn dns_event(eve: &Eve, base: EcsEvent) -> Result<EcsEvent, NormaliseError> {
    let dns = eve.dns.as_ref().ok_or(NormaliseError::MissingField("dns"))?;
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
    Ok(EcsEvent {
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
    })
}


fn http_event(eve: &Eve, base: EcsEvent) -> Result<EcsEvent, NormaliseError> {
    let http = eve.http.as_ref().ok_or(NormaliseError::MissingField("http"))?;
    let url = clean_opt(http.url.as_ref());
    Ok(EcsEvent {
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
                status_code: http.status,
                body: non_empty(HttpBodyFields { bytes: http.length }),
            }),
        }),
        user_agent: non_empty(UserAgentFields {
            original: clean_opt(http.http_user_agent.as_ref()),
        }),
        ..base
    })
}


fn ja_hash(ja: Option<&Ja>) -> Option<JaHash> {
    ja.and_then(|found| {
        non_empty(JaHash {
            hash: clean_opt(found.hash.as_ref()),
        })
    })
}


fn tls_event(eve: &Eve, base: EcsEvent) -> Result<EcsEvent, NormaliseError> {
    let tls = eve.tls.as_ref().ok_or(NormaliseError::MissingField("tls"))?;
    Ok(EcsEvent {
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
    })
}


/// Maps one parsed EVE record to an ECS event; an event type outside the five mapped ones is `Unknown("suricata:<type>")`.
pub fn convert_eve(eve: &Eve) -> Result<Outcome, NormaliseError> {
    let mapped = match eve.event_type.as_str() {
        "alert" => Some(alert_event(eve, base_event(eve, &[]))),
        "flow" => Some(flow_event(eve, base_event(eve, &["connection", "end"]))),
        "dns" => Some(dns_event(eve, base_event(eve, &["protocol"]))),
        "http" => Some(http_event(eve, base_event(eve, &["protocol"]))),
        "tls" => Some(tls_event(eve, base_event(eve, &["protocol"]))),
        _ => None,
    };
    match mapped {
        Some(result) => result.map(|event| Outcome::Event(Box::new(event))),
        None => Ok(Outcome::Unknown(format!("{MODULE}:{}", clean(&eve.event_type)))),
    }
}


/// Parses one EVE line: `Syntax` is invalid JSON, `Schema` is valid JSON of the wrong shape (a bad port, number or timestamp included).
pub fn parse_eve(text: &str) -> Result<Outcome, NormaliseError> {
    let value: Value = from_str(text).map_err(NormaliseError::Syntax)?;
    let eve: Eve = from_value(value).map_err(NormaliseError::Schema)?;
    convert_eve(&eve)
}
