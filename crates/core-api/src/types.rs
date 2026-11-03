use crate::model::{ApiState, Rule};
use core_auth::error::AuthError;
use governor::DefaultKeyedRateLimiter;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;


pub type SharedState = Arc<ApiState>;


pub type KeyedLimiter = DefaultKeyedRateLimiter<IpAddr>;


pub type ServerHandle = axum_server::Handle<SocketAddr>;


pub type AccessTable = BTreeMap<String, Rule>;


pub type VerifyPasswordFn = fn(&str, &str) -> Result<bool, AuthError>;
