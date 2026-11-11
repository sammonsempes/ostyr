use crate::error::ExportError;
use crate::types::LabelMap;
use serde::Serialize;
use time::OffsetDateTime;


pub const ECS_VERSION: &str = "8.11";


#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EcsMeta {
    pub version: String,
}


impl Default for EcsMeta {
    fn default() -> Self {
        Self {
            version: ECS_VERSION.to_string(),
        }
    }
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EventFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub category: Vec<String>,
    #[serde(rename = "type", skip_serializing_if = "Vec::is_empty")]
    pub types: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dataset: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub module: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none", with = "time::serde::rfc3339::option")]
    pub start: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none", with = "time::serde::rfc3339::option")]
    pub end: Option<OffsetDateTime>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HostFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub ip: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<OsFields>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct OsFields {
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UserFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
}


/// Used for both `source.*` and `destination.*`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct EndpointFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub packets: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ProcessFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_directory: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<HashFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pe: Option<PeFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent: Option<ParentFields>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HashFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub md5: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha1: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct PeFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original_file_name: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ParentFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entity_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub executable: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct NetworkFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub transport: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub community_id: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FileFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<HashFields>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RegistryFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DnsQuestion {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DnsFields {
    pub question: DnsQuestion,
    #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_code: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub resolved_ip: Vec<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UrlFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HttpRequestFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HttpBodyFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes: Option<u64>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HttpResponseFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<HttpBodyFields>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HttpFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request: Option<HttpRequestFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response: Option<HttpResponseFields>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct JaHash {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hash: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TlsClientFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3: Option<JaHash>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TlsServerFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_after: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ja3s: Option<JaHash>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct TlsFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<TlsClientFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server: Option<TlsServerFields>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct RuleFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct UserAgentFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub original: Option<String>,
}


/// An ECS 8.x event; every optional part that is `None` or empty is left out of the JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EcsEvent {
    #[serde(rename = "@timestamp", with = "time::serde::rfc3339")]
    pub timestamp: OffsetDateTime,
    pub ecs: EcsMeta,
    pub event: EventFields,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<HostFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<UserFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<EndpointFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<EndpointFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<NetworkFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<FileFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<RegistryFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<UrlFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http: Option<HttpFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<RuleFields>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<UserAgentFields>,
    #[serde(skip_serializing_if = "LabelMap::is_empty")]
    pub labels: LabelMap,
    #[serde(skip_serializing_if = "LabelMap::is_empty")]
    pub sysmon: LabelMap,
}


/// An event with only the mandatory parts; `OffsetDateTime` has no `Default`, so struct update syntax starts from this.
pub fn blank_event(timestamp: OffsetDateTime) -> EcsEvent {
    EcsEvent {
        timestamp,
        ecs: EcsMeta::default(),
        event: EventFields::default(),
        message: None,
        host: None,
        user: None,
        source: None,
        destination: None,
        network: None,
        process: None,
        file: None,
        registry: None,
        dns: None,
        url: None,
        http: None,
        tls: None,
        rule: None,
        user_agent: None,
        labels: LabelMap::new(),
        sysmon: LabelMap::new(),
    }
}


pub fn to_json(event: &EcsEvent) -> Result<String, ExportError> {
    serde_json::to_string(event).map_err(ExportError::from)
}
