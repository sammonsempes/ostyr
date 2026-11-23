use crate::fetch_error::{HttpFailure, LedgerFailure};
use crate::fetch_model::{HttpRequest, HttpResponse};
use crate::load::{LoadError, LoadOutcome};
use crate::model::SkipReason;
use crate::source::Export;
use rust_decimal::Decimal;
use std::collections::BTreeMap;
use time::Date;


pub type CostKey = (Date, String, String);


pub type CostMap = BTreeMap<CostKey, Decimal>;


pub type DayMap = BTreeMap<Date, Decimal>;


/// First and last day of a range.
pub type DayRange = (Date, Date);


pub type SkipCounts = BTreeMap<SkipReason, u64>;


/// One stored aggregate key: day, billing account label, dimension, and the two key parts.
pub type StoredKey = (Date, String, &'static str, String, String);


pub type StoredMap = BTreeMap<StoredKey, Decimal>;


/// A cost point before the common columns are added: day, dimension, the two key parts and the amount.
pub type Point = (Date, String, &'static str, String, String, Decimal);


pub type HttpFn<'a> = dyn Fn(&HttpRequest) -> Result<HttpResponse, HttpFailure> + 'a;


/// The PostgreSQL ledger executor: a statement with `$n` text parameters in, rows of text columns out.
pub type ExecFn<'a> = dyn Fn(&str, &[String]) -> Result<Vec<Vec<String>>, LedgerFailure> + 'a;


/// The ClickHouse load of one export for one tenant.
pub type LoadFn<'a> = dyn Fn(&str, &Export) -> Result<LoadOutcome, LoadError> + 'a;


/// The tenant's load states as one pair: row count and sum of generations.
pub type LoadStamp = (u64, u64);


/// The time spent so far under one deadline, injected so tests never read the clock.
pub type ElapsedFn<'a> = dyn Fn() -> std::time::Duration + 'a;
