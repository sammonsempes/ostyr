use crate::params::Resolved;
use serde_json::Value;
use std::collections::BTreeMap;


pub type ParamMap = BTreeMap<String, Value>;


pub type ResolvedMap = BTreeMap<String, Resolved>;
