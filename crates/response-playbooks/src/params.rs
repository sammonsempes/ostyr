use crate::expr::{is_template, resolve, Scope, DISPLAY_KEY};
use crate::model::{CatalogueEntry, ParamType};
use crate::types::{ParamMap, ResolvedMap};
use serde_json::Value;
use std::net::IpAddr;
use std::time::Duration;


pub const TAGS_KEY: &str = "tags";


#[derive(Debug, Clone, PartialEq)]
pub struct Resolved {
    pub value: Value,
    pub tags: Vec<String>,
}


pub fn type_label(kind: ParamType) -> &'static str {
    match kind {
        ParamType::String => "a string",
        ParamType::Integer => "an integer",
        ParamType::Boolean => "a boolean",
        ParamType::Ip => "an IP address",
        ParamType::Domain => "a domain name",
        ParamType::Duration => "a duration such as 15m or 24h",
    }
}


pub fn as_ip(value: &Value) -> Option<IpAddr> {
    value.as_str().and_then(|text| text.parse().ok())
}


pub fn as_duration(value: &Value) -> Option<Duration> {
    value.as_str().and_then(|text| humantime::parse_duration(text).ok())
}


pub fn as_count(value: &Value) -> Option<u64> {
    value.as_u64().or_else(|| value.as_str().and_then(|text| text.parse().ok()))
}


pub fn is_boolean(value: &Value) -> bool {
    value.is_boolean() || matches!(value.as_str(), Some("true" | "false"))
}


pub fn is_domain(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.is_empty() && !text.contains(char::is_whitespace))
}


pub fn conforms(kind: ParamType, value: &Value) -> bool {
    match kind {
        ParamType::String => value.is_string(),
        ParamType::Integer => as_count(value).is_some(),
        ParamType::Boolean => is_boolean(value),
        ParamType::Ip => as_ip(value).is_some(),
        ParamType::Domain => is_domain(value),
        ParamType::Duration => as_duration(value).is_some(),
    }
}


pub fn check_type(kind: ParamType, value: &Value) -> Result<(), String> {
    conforms(kind, value)
        .then_some(())
        .ok_or_else(|| format!("expected {}, found {value}", type_label(kind)))
}


pub fn is_empty(value: &Value) -> bool {
    value.is_null() || value.as_str().is_some_and(str::is_empty)
}


pub fn tags_of(entity: &Value) -> Vec<String> {
    entity
        .get(TAGS_KEY)
        .and_then(Value::as_array)
        .map_or_else(Vec::new, |tags| tags.iter().filter_map(Value::as_str).map(str::to_owned).collect())
}


/// An entity map yields its `value` member as the parameter and its `tags` for the breakers.
pub fn reduce_entity(value: Value) -> Resolved {
    match value.get(DISPLAY_KEY).cloned() {
        Some(inner) => Resolved {
            value: inner,
            tags: tags_of(&value),
        },
        None => Resolved { value, tags: Vec::new() },
    }
}


pub fn resolve_one(raw: &Value, scope: &Scope) -> Result<Value, String> {
    match raw {
        Value::String(text) if is_template(text) => resolve(text, scope).map_err(|failure| failure.to_string()),
        literal => Ok(literal.clone()),
    }
}


/// Every parameter of the catalogue entry is resolved, typed and checked; the first problem is the error.
pub fn resolve_params(entry: &CatalogueEntry, params: &ParamMap, scope: &Scope) -> Result<ResolvedMap, String> {
    params
        .keys()
        .find(|name| !entry.params.contains_key(*name))
        .map_or(Ok(()), |name| Err(format!("unknown parameter `{name}`")))?;
    entry.params.iter().try_fold(ResolvedMap::new(), |mut resolved, (name, spec)| {
        let found = params
            .get(name)
            .map(|raw| resolve_one(raw, scope))
            .transpose()
            .map_err(|failure| format!("parameter `{name}`: {failure}"))?
            .map(reduce_entity)
            .filter(|candidate| !is_empty(&candidate.value));
        match found {
            Some(candidate) => check_type(spec.kind, &candidate.value)
                .map(|()| {
                    resolved.insert(name.clone(), candidate);
                    resolved
                })
                .map_err(|failure| format!("parameter `{name}`: {failure}")),
            None if spec.optional => Ok(resolved),
            None => Err(format!("parameter `{name}` is missing or empty")),
        }
    })
}
