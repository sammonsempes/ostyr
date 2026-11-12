use crate::model::SkipReason;
use rust_decimal::Decimal;
use std::collections::BTreeMap;
use time::Date;


pub type CostKey = (Date, String, String);


pub type CostMap = BTreeMap<CostKey, Decimal>;


pub type DayMap = BTreeMap<Date, Decimal>;


pub type SkipCounts = BTreeMap<SkipReason, u64>;
