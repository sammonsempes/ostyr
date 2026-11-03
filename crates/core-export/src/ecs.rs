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
    pub severity: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sequence: Option<u64>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct HostFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
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
    pub parent: Option<ParentFields>,
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ParentFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<u32>,
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
}


#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct FileFields {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
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
    #[serde(skip_serializing_if = "LabelMap::is_empty")]
    pub labels: LabelMap,
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
        labels: LabelMap::new(),
    }
}


pub fn to_json(event: &EcsEvent) -> Result<String, ExportError> {
    serde_json::to_string(event).map_err(ExportError::from)
}
