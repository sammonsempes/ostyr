use crate::model::SkipReason;
use rust_decimal::Decimal;
use std::collections::BTreeMap;
use time::Date;


pub type CostKey = (Date, String, String);


pub type CostMap = BTreeMap<CostKey, Decimal>;


pub type DayMap = BTreeMap<Date, Decimal>;


pub type SkipCounts = BTreeMap<SkipReason, u64>;


/// One stored aggregate key: day, billing account label, dimension, and the two key parts.
pub type StoredKey = (Date, String, &'static str, String, String);


pub type StoredMap = BTreeMap<StoredKey, Decimal>;


/// A cost point before the common columns are added: day, dimension, the two key parts and the amount.
pub type Point = (Date, String, &'static str, String, String, Decimal);
