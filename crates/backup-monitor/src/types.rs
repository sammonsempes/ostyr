use crate::model::SkipReason;
use std::collections::BTreeMap;
use time::OffsetDateTime;


pub type SkipCounts = BTreeMap<SkipReason, u64>;


pub type Clock = fn() -> OffsetDateTime;
