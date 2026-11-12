use crate::types::{CostMap, DayMap, DayRange, SkipCounts, StoredMap};
use core_pg::scope::TenantScope;
use rust_decimal::Decimal;
use serde::Deserialize;
use std::collections::BTreeSet;
use time::{Date, Month};


pub const DEFAULT_MAX_BYTES: u64 = 536_870_912;


pub const DEFAULT_MAX_ROWS: u64 = 5_000_000;


pub const DEFAULT_MAX_FIELD_BYTES: usize = 1024;


pub const DEFAULT_MAX_TAGS_PER_ROW: usize = 32;


pub const DEFAULT_MAX_SERIES: usize = 1000;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Limits {
    pub max_bytes: u64,
    pub max_rows: u64,
    pub max_field_bytes: usize,
    pub max_tags_per_row: usize,
    pub max_series: usize,
}


impl Default for Limits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_BYTES,
            max_rows: DEFAULT_MAX_ROWS,
            max_field_bytes: DEFAULT_MAX_FIELD_BYTES,
            max_tags_per_row: DEFAULT_MAX_TAGS_PER_ROW,
            max_series: DEFAULT_MAX_SERIES,
        }
    }
}


pub const DIMENSION_TOTAL: &str = "total";


pub const DIMENSION_ACCOUNT_SERVICE: &str = "account_service";


pub const DIMENSION_TAG: &str = "tag";


pub const DIMENSION_OTHER: &str = "other";


pub const DIMENSION_TAG_OTHER: &str = "tag_other";


#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SkipReason {
    Oversized,
    Malformed,
    BadAmount,
    BadDate,
    BadTags,
    MixedCurrency,
}


/// Cost that fell outside the series caps, with the number of rows or tag pairs it came from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OtherBucket {
    pub cost: Decimal,
    pub count: u64,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostTable {
    pub tenant: TenantScope,
    pub currency: Option<String>,
    pub accepted: u64,
    pub day_totals: DayMap,
    pub by_account_service: CostMap,
    pub by_tag: CostMap,
    pub account_rows: StoredMap,
    pub seen_accounts: BTreeSet<String>,
    pub seen_days: Option<DayRange>,
    pub other: OtherBucket,
    pub tag_other: OtherBucket,
    pub skipped: SkipCounts,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Columns {
    pub amount: usize,
    pub currency: usize,
    pub account: usize,
    pub start: usize,
    pub service: usize,
    pub tags: Option<usize>,
    pub sub_account: Option<usize>,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub day: Date,
    pub account: String,
    pub service: String,
    pub currency: String,
    pub amount: Decimal,
    pub tags: Vec<(String, String)>,
}


#[derive(Debug)]
pub struct State {
    pub table: CostTable,
    pub rows: u64,
    pub accounts: BTreeSet<String>,
    pub services: BTreeSet<String>,
    pub pairs: BTreeSet<(String, String)>,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TagScope {
    pub key: String,
    pub value: String,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    Account(String),
    Service(String),
    Tag(TagScope),
    All,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DailyChange {
    #[serde(deserialize_with = "crate::budget::amount_field")]
    pub factor: Decimal,
    #[serde(deserialize_with = "crate::budget::amount_field")]
    pub min_amount: Decimal,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    pub name: String,
    pub scope: Scope,
    #[serde(deserialize_with = "crate::budget::amount_field")]
    pub monthly: Decimal,
    pub currency: String,
    pub thresholds: Vec<u32>,
    pub daily_change: DailyChange,
}


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budgets {
    pub budgets: Vec<Budget>,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MonthKey {
    pub year: i32,
    pub month: Month,
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AlertKind {
    Threshold { percent: u32, spent: Decimal, limit: Decimal },
    AbnormalDay { day: Date, cost: Decimal, median: Decimal },
}


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostAlert {
    pub tenant: TenantScope,
    pub budget: String,
    pub kind: AlertKind,
}
