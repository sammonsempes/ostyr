use crate::model::{NeighbourId, RunFailure};
use serde_json::value::RawValue;


pub type LinkKey = (String, String, NeighbourId, NeighbourId);


pub type PortKey = (String, String);


pub type RawList<'a> = Vec<&'a RawValue>;


pub type AnyError = Box<dyn std::error::Error + Send + Sync>;


pub type RunPortFn = fn(&str, u64, std::time::Duration) -> Result<Vec<u8>, RunFailure>;


pub type ClockFn<'a> = &'a mut dyn FnMut() -> std::time::Instant;
