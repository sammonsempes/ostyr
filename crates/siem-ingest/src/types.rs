use crate::model::Document;
use core_config::types::BoxError;
use std::time::Duration;
use time::OffsetDateTime;


pub type AckToken = u64;


pub type ClockFn = dyn Fn() -> OffsetDateTime + Send + Sync;


pub type SinkFn = dyn Fn(&str, &[Document]) -> Result<(), BoxError> + Send + Sync;


pub type SleepFn = dyn Fn(Duration) + Send + Sync;
