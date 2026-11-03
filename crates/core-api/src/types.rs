use crate::model::{ApiState, Rule};
use governor::DefaultKeyedRateLimiter;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;


pub type SharedState = Arc<ApiState>;


pub type KeyedLimiter = DefaultKeyedRateLimiter<IpAddr>;


pub type ServerHandle = axum_server::Handle<SocketAddr>;


pub type AccessTable = BTreeMap<String, Rule>;
