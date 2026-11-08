//! Type aliases.

use crate::model::UnmatchedReason;
use std::collections::BTreeMap;


pub type UnmatchedCounts = BTreeMap<UnmatchedReason, usize>;
