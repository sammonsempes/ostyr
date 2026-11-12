use crate::model::SkipReason;
use std::collections::BTreeMap;


pub type SkipCounts = BTreeMap<SkipReason, u64>;
