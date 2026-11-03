use crate::types::ParameterMap;
use serde::Deserialize;
use time::OffsetDateTime;


pub const GENESIS_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ActorKind {
    User,
    Ai,
    System,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Outcome {
    Success,
    Failure,
    Denied,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Actor {
    pub kind: ActorKind,
    pub id: String,
}


/// What a caller supplies; the chain fields are added by `append`.
#[derive(Debug, Clone)]
pub struct NewEntry {
    pub timestamp: OffsetDateTime,
    pub actor: Actor,
    pub tenant: String,
    pub module: String,
    pub action: String,
    pub target: String,
    pub outcome: Outcome,
    pub request_id: String,
    pub justification: Option<String>,
    pub parameters: ParameterMap,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub timestamp: String,
    pub actor_kind: ActorKind,
    pub actor_id: String,
    pub tenant: String,
    pub module: String,
    pub action: String,
    pub target: String,
    pub outcome: Outcome,
    pub request_id: String,
    pub justification: Option<String>,
    pub parameters: ParameterMap,
    pub previous_hash: String,
    pub hash: String,
}
