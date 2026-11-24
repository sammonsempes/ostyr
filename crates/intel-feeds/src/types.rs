use crate::config::{ClickhouseConfig, FeedConfig, FeedsFile};
use crate::error::EntryError;
use crate::export::ExportSummary;
use crate::load::{LoadError, LoadOutcome};
use crate::model::{FeedSummary, Ioc, IocType, RawEntry};
use crate::retro::{RetroError, RetroReply, RetroRequest, RetroRun, RetroSettings};
use alerts::error::StoreError;
use alerts::model::Alert;
use core_pg::scope::TenantScope;
use serde_json::Value;
use siem_ingest::error::InsertClass;
use std::collections::BTreeMap;
use std::io::{self, BufRead};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use ureq::http::StatusCode;


pub type IocKey = (IocType, String);


pub type IocIndex = BTreeMap<IocKey, Ioc>;


pub type OpenFn<'a> = dyn Fn(&Path) -> io::Result<Box<dyn BufRead>> + 'a;


pub type ClockFn<'a> = dyn Fn() -> OffsetDateTime + 'a;


pub type LineHandler<'a> = dyn FnMut(&str) -> Result<Option<RawEntry>, EntryError> + 'a;


pub type ItemHandler<'a> = dyn Fn(&Value) -> Result<Vec<Ioc>, EntryError> + 'a;


pub type ExportRun = (Vec<FeedSummary>, ExportSummary);


pub type TtlDefaults = BTreeMap<String, u32>;


pub type LoadFn<'a> = dyn Fn(&ClickhouseConfig, &[Ioc], &[FeedConfig], OffsetDateTime) -> Result<LoadOutcome, LoadError> + 'a;


pub type RetroSendFn<'a> = dyn Fn(&RetroRequest) -> Result<RetroReply, InsertClass> + 'a;


pub type ElapsedFn<'a> = dyn Fn() -> Duration + 'a;


pub type RefusalFn = fn(StatusCode, Option<u32>) -> Option<RetroError>;


/// Inserts one run's alerts under the tenant scope and answers how many were new; the example owns the runtime that drives `alerts::store::insert_alerts`.
pub type AlertInsertFn<'a> = dyn Fn(&TenantScope, &[Alert]) -> Result<usize, StoreError> + 'a;


pub type RunRetroFn<'a> = dyn Fn(&RetroSettings, OffsetDateTime, OffsetDateTime, Option<OffsetDateTime>) -> Result<RetroRun, RetroError> + 'a;


pub type WaitFn<'a> = dyn Fn(Duration) + 'a;


pub type StopFn<'a> = dyn Fn() -> bool + 'a;


pub type SnapshotFn<'a> = dyn Fn() -> Option<Arc<FeedsFile>> + 'a;
