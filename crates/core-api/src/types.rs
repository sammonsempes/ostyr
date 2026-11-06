use crate::model::{ApiState, Rule, Window};
use core_auth::error::AuthError;
use core_config::secret::SecretRef;
use openidconnect::{HttpRequest, HttpResponse};
use secrecy::SecretString;
use std::collections::BTreeMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};


pub type SharedState = Arc<ApiState>;


pub type KeyedLimiter = Mutex<BTreeMap<IpAddr, Window>>;


pub type ConnectionTable = Arc<Mutex<BTreeMap<IpAddr, usize>>>;


pub type ServerHandle = axum_server::Handle<SocketAddr>;


pub type AccessTable = BTreeMap<String, Rule>;


pub type VerifyPasswordFn = fn(&str, &str) -> Result<bool, AuthError>;


pub type SharedHttpFn = Box<dyn Fn(HttpRequest) -> Result<HttpResponse, io::Error> + Send + Sync>;


pub type SharedResolveFn = Box<dyn Fn(&SecretRef) -> Result<SecretString, io::Error> + Send + Sync>;
