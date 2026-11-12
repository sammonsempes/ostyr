use crate::error::StoreError;
use crate::model::{IncidentInput, PageSettings, PageState};
use arc_swap::ArcSwap;
use core_pg::scope::TenantScope;
use std::collections::{BTreeMap, HashMap};
use std::error::Error;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use tokio::net::TcpStream;
use tokio_stream::Stream;


pub type SharedSettings = Arc<ArcSwap<PageSettings>>;


/// Open connections per source key; an entry exists only while it holds one, so the table never outgrows `max_connections`.
pub type SourceConnections = Arc<Mutex<HashMap<IpAddr, usize>>>;


pub type SharedState = Arc<PageState>;


pub type BoxError = Box<dyn Error + Send + Sync>;


/// Reads the limiter clock in milliseconds; production passes `system_millis`.
pub type NowFn = dyn Fn() -> u64 + Send + Sync;


pub type IncomingConnections = Pin<Box<dyn Stream<Item = io::Result<TcpStream>> + Send>>;


pub type ShutdownSignal = Pin<Box<dyn Future<Output = ()> + Send>>;


pub type ReadFuture = Pin<Box<dyn Future<Output = Result<Vec<IncidentInput>, StoreError>> + Send>>;


/// Reads the published incidents of the tenant scope it is given; production connects to PostgreSQL, tests answer from memory.
pub type IncidentReadFn = Box<dyn Fn(TenantScope) -> ReadFuture + Send + Sync>;


pub type Row = Vec<crate::store_model::Cell>;


/// Samples (newest first) per (check, location).
pub type Series<'a> = BTreeMap<(&'a str, &'a str), Vec<(i64, bool)>>;
