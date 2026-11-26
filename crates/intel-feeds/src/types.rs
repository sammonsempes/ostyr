use crate::budget::Stored;
use crate::config::{ClickhouseConfig, FeedConfig, FeedsFile};
use crate::error::{EntryError, TaxiiError};
use crate::export::ExportSummary;
use crate::load::{LoadError, LoadOutcome};
use crate::misp::TlpReading;
use crate::model::{FeedSummary, Ioc, IocType, RawEntry};
use crate::read::ReadError;
use crate::retro::{RetroError, RetroReply, RetroRequest, RetroRun, RetroSettings};
use crate::taxii::PollOutcome;
use alerts::error::StoreError;
use alerts::model::Alert;
use core_pg::scope::TenantScope;
use serde_json::value::RawValue;
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


pub type ItemHandler<'a> = dyn Fn(&Value, TlpReading) -> Result<Vec<Ioc>, EntryError> + 'a;


/// One raw list element with the TLP floor that applies to it.
pub type Tagged<'a> = (&'a RawValue, TlpReading);


pub type ExportRun = (Vec<FeedSummary>, ExportSummary);


pub type TtlDefaults = BTreeMap<String, u32>;


pub type LoadFn<'a> = dyn Fn(&ClickhouseConfig, &[Ioc], &[FeedConfig], OffsetDateTime) -> Result<LoadOutcome, LoadError> + 'a;


/// The tenant's stored rows at the start of a round, or why they cannot be read.
pub type StoredFn<'a> = dyn Fn(&ClickhouseConfig, OffsetDateTime) -> Result<Stored, ReadError> + 'a;


pub type RetroSendFn<'a> = dyn Fn(&RetroRequest) -> Result<RetroReply, InsertClass> + 'a;


pub type ElapsedFn<'a> = dyn Fn() -> Duration + 'a;


pub type RefusalFn = fn(StatusCode, Option<u32>) -> Option<RetroError>;


/// Inserts one run's alerts under the tenant scope and answers how many were new; the example owns the runtime that drives `alerts::store::insert_alerts`.
pub type AlertInsertFn<'a> = dyn Fn(&TenantScope, &[Alert]) -> Result<usize, StoreError> + 'a;


pub type RunRetroFn<'a> = dyn Fn(&RetroSettings, OffsetDateTime, OffsetDateTime, Option<OffsetDateTime>) -> Result<RetroRun, RetroError> + 'a;


pub type WaitFn<'a> = dyn Fn(Duration) + 'a;


/// Run once when the loop ends, before the reload gate is taken.
pub type EndFn<'a> = dyn Fn() + 'a;


pub type StopFn<'a> = dyn Fn() -> bool + 'a;


pub type SnapshotFn<'a> = dyn Fn() -> Option<Arc<FeedsFile>> + 'a;


/// Saves the tenant and the end of a successful window; a failure is logged by the schedule and never stops it.
pub type SaveEndFn<'a> = dyn Fn(&str, OffsetDateTime) -> io::Result<()> + 'a;


pub type PollFn<'a> = dyn Fn(&FeedConfig, Option<OffsetDateTime>, OffsetDateTime) -> Result<PollOutcome, TaxiiError> + 'a;


/// A TAXII feed's name and the rendering of its whole parsed configuration.
pub type CursorKey = (String, String);


/// The `added_after` cursor of each TAXII source by its whole configuration, in memory only.
pub type Cursors = BTreeMap<CursorKey, OffsetDateTime>;


/// Waits at most the duration and answers true when a stop was requested.
pub type StopWaitFn<'a> = dyn Fn(Duration) -> bool + 'a;
