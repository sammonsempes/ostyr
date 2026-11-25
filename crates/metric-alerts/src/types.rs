use crate::fetch::FetchError;
use crate::query::MetricQuery;
use crate::round::RoundStates;
use crate::service::{Live, PassReport};
use std::collections::BTreeMap;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::time::Duration;


pub type Timestamp = u64;


pub type Point = (Timestamp, f64);


pub type Labels = BTreeMap<String, String>;


pub type QueryParams = Vec<(String, String)>;


pub type FetchResult = Result<Vec<Point>, FetchError>;


/// Runs one query for a round; production wraps `fetch_points`, tests answer from a script.
pub type FetchFn<'a> = &'a dyn Fn(&MetricQuery) -> FetchResult;


pub type ElapsedFn<'a> = dyn Fn() -> Duration + 'a;


/// The wall clock in seconds, one reading per round.
pub type NowFn<'a> = dyn Fn() -> Timestamp + 'a;


pub type PassFuture = Pin<Box<dyn Future<Output = PassReport>>>;


/// Runs one pass over every tenant for a snapshot at a reading of the clock.
pub type PassFn<'a> = dyn FnMut(Live, Timestamp) -> PassFuture + 'a;


/// The sleep between two rounds.
pub type WaitFn<'a> = dyn Fn(Duration) -> Pin<Box<dyn Future<Output = ()>>> + 'a;


pub type LiveFn<'a> = dyn Fn() -> Live + 'a;


/// One `RoundStates` per tenant name, never shared between tenants.
pub type TenantStates = BTreeMap<String, RoundStates>;


pub type InterruptWait = Pin<Box<dyn Future<Output = io::Result<()>>>>;
