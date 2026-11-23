use crate::cardinality::CardinalityState;
use crate::model::{DropReason, Limits, Outcome};
use crate::run::{RunError, RunReport};
use prost::DecodeError;
use serde::de::IgnoredAny;
use serde_json::value::RawValue;
use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;


pub type LabelMap = BTreeMap<String, String>;


pub type ResourceLabels = Result<LabelMap, DropReason>;


pub type Labels = Vec<(String, String)>;


pub type SeriesKey = (String, Labels);


pub type Dropped = BTreeMap<DropReason, u64>;


pub type TenantMonth = (String, i32, u8);


pub type Groups = BTreeMap<TenantMonth, Vec<Vec<u8>>>;


pub type ElapsedFn<'a> = dyn Fn() -> Duration + 'a;


pub type LimitRow = (&'static str, u64, u64, u64);


/// One wire field: its tag and its payload when length-delimited; the length is validated against the buffer.
pub type WireField<'a> = Result<(u32, Option<&'a [u8]>), DecodeError>;


pub type RawField = Option<Box<RawValue>>;


pub type BuildFn<'a> = dyn Fn(&[u8], &str, &Limits, &mut CardinalityState) -> Outcome + 'a;


pub type RunFn<'a> = dyn Fn(&Path, &[u8], &str, &mut CardinalityState, u64, &ElapsedFn) -> Result<RunReport, RunError> + 'a;


pub type KeySet = BTreeMap<String, IgnoredAny>;
