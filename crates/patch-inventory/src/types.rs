//! Type aliases.

use crate::model::SkipReason;
use std::collections::BTreeMap;


pub type SkipCounts = BTreeMap<SkipReason, usize>;


pub type UpdateKey = (String, String);
