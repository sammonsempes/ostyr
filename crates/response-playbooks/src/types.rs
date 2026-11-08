use crate::error::ConnectorError;
use crate::model::{ConnectorCall, ConnectorResult};
use crate::params::Resolved;
use serde_json::Value;
use std::collections::BTreeMap;
use std::time::Duration;


pub type ParamMap = BTreeMap<String, Value>;


pub type ResolvedMap = BTreeMap<String, Resolved>;


pub type ConnectorFn = dyn Fn(&ConnectorCall) -> Result<ConnectorResult, ConnectorError> + Send + Sync;


pub type MonotonicFn = dyn Fn() -> Duration + Send + Sync;
