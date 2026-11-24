use crate::model::{Prepared, Session, WebState, Window};
use core_auth::types::RandomFn;
use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};


pub type ClockFn = Box<dyn Fn() -> u64 + Send + Sync>;


pub type WallFn = Box<dyn Fn() -> i64 + Send + Sync>;


pub type SessionTable = Mutex<BTreeMap<String, Session>>;


pub type AttemptTable = Mutex<BTreeMap<IpAddr, Window>>;


pub type PendingRuntime = Arc<Mutex<Option<Prepared>>>;


pub type Random = RandomFn;


pub type Form = BTreeMap<String, String>;


pub type TextTable = [(&'static str, &'static str)];


pub type Refused = Box<axum::response::Response>;


pub type SharedWeb = Arc<WebState>;


/// Resolves when the process is asked to stop; production passes `tokio::signal::ctrl_c()`, a test passes a ready value.
pub type InterruptWait = Pin<Box<dyn Future<Output = io::Result<()>> + Send>>;
