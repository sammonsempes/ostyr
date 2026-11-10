use crate::model::{Prepared, Session, WebState, Window};
use core_auth::types::RandomFn;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};


pub type ClockFn = Box<dyn Fn() -> u64 + Send + Sync>;


pub type SessionTable = Mutex<BTreeMap<String, Session>>;


pub type AttemptTable = Mutex<BTreeMap<IpAddr, Window>>;


pub type PendingRuntime = Arc<Mutex<Option<Prepared>>>;


pub type Random = RandomFn;


pub type Form = BTreeMap<String, String>;


pub type TextTable = [(&'static str, &'static str)];


pub type Refused = Box<axum::response::Response>;


pub type SharedWeb = Arc<WebState>;
