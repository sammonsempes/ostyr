use crate::model::{AckAction, Delivery, Document, Message};
use core_config::types::BoxError;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use time::OffsetDateTime;


pub type AckToken = u64;


pub type ClockFn = dyn Fn() -> OffsetDateTime + Send + Sync;


pub type SinkFn = dyn Fn(&str, &[Document]) -> Result<(), BoxError> + Send + Sync;


pub type SleepFn = dyn Fn(Duration) + Send + Sync;


pub type FetchFn = dyn FnMut(usize) -> Result<Vec<Delivery>, BoxError> + Send;


pub type AckFn = dyn Fn(AckToken, AckAction) -> Result<(), BoxError> + Send + Sync;


pub type DeadLetterFn = dyn Fn(&str, &[u8], &str) -> Result<(), BoxError> + Send + Sync;


pub type StopFn = dyn Fn() -> bool;


pub type PendingMap = HashMap<AckToken, Message>;


pub type Counts = Arc<Mutex<BTreeMap<String, usize>>>;


pub type ConnectionFields<'a> = (
    (&'a str, bool, Option<&'a Path>, Option<&'a Path>, Option<&'a str>, Option<&'a Path>),
    (&'a str, &'a str, u64, u64, u64, usize),
);
