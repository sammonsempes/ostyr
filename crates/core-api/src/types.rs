use crate::model::{ApiState, Limits, Listener, PreparedAudit, PreparedKey, Rule, Sockets, Window};
use arc_swap::ArcSwap;
use core_auth::error::AuthError;
use core_config::secret::SecretRef;
use openidconnect::{HttpRequest, HttpResponse};
use secrecy::SecretString;
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};


pub type SharedState = Arc<ApiState>;


pub type PendingGenerations = Mutex<BTreeMap<String, u64>>;


pub type KeyedLimiter = Mutex<BTreeMap<IpAddr, Window>>;


pub type ConnectionTable = Arc<Mutex<BTreeMap<IpAddr, usize>>>;


pub type ServerHandle = axum_server::Handle<SocketAddr>;


pub type AccessTable = BTreeMap<String, Rule>;


pub type VerifyPasswordFn = fn(&str, &str) -> Result<bool, AuthError>;


pub type SharedHttpFn = Box<dyn Fn(HttpRequest) -> Result<HttpResponse, io::Error> + Send + Sync>;


pub type SharedLimits = Arc<ArcSwap<Limits>>;


pub type LogLevelHandle = tracing_subscriber::reload::Handle<tracing::level_filters::LevelFilter, tracing_subscriber::Registry>;


pub type SharedResolveFn = Box<dyn Fn(&SecretRef) -> Result<SecretString, io::Error> + Send + Sync>;


pub type SharedListener = Arc<Listener>;


pub type PendingSockets = Arc<Mutex<Option<Sockets>>>;


pub type PendingAudit = Arc<Mutex<Option<PreparedAudit>>>;


pub type WatchGuard = Box<dyn Send>;


pub type PendingKey = Arc<Mutex<Option<PreparedKey>>>;
