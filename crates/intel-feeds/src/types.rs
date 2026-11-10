use crate::config::{ClickhouseConfig, FeedConfig};
use crate::error::EntryError;
use crate::export::ExportSummary;
use crate::load::{LoadError, LoadOutcome};
use crate::model::{FeedSummary, Ioc, IocType, RawEntry};
use serde_json::Value;
use std::collections::BTreeMap;
use std::io::{self, BufRead};
use std::path::Path;
use time::OffsetDateTime;


pub type IocKey = (IocType, String);


pub type IocIndex = BTreeMap<IocKey, Ioc>;


pub type OpenFn<'a> = dyn Fn(&Path) -> io::Result<Box<dyn BufRead>> + 'a;


pub type ClockFn<'a> = dyn Fn() -> OffsetDateTime + 'a;


pub type LineHandler<'a> = dyn FnMut(&str) -> Result<Option<RawEntry>, EntryError> + 'a;


pub type ItemHandler<'a> = dyn Fn(&Value) -> Result<Vec<Ioc>, EntryError> + 'a;


pub type ExportRun = (Vec<FeedSummary>, ExportSummary);


pub type TtlDefaults = BTreeMap<String, u32>;


pub type LoadFn<'a> = dyn Fn(&ClickhouseConfig, &[Ioc], &[FeedConfig], OffsetDateTime) -> Result<LoadOutcome, LoadError> + 'a;
