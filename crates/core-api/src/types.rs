use crate::model::{ApiState, Rule, Window};
use core_auth::error::AuthError;
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};


pub type SharedState = Arc<ApiState>;


pub type KeyedLimiter = Mutex<BTreeMap<IpAddr, Window>>;


pub type ConnectionTable = Arc<Mutex<BTreeMap<IpAddr, usize>>>;


pub type ServerHandle = axum_server::Handle<SocketAddr>;


pub type AccessTable = BTreeMap<String, Rule>;


pub type VerifyPasswordFn = fn(&str, &str) -> Result<bool, AuthError>;
