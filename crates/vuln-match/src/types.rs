//! Type aliases.

use crate::error::StoreError;
use crate::model::UnmatchedReason;
use std::collections::BTreeMap;


pub type UnmatchedCounts = BTreeMap<UnmatchedReason, usize>;


pub type CursorSplit = for<'a> fn(&'a str) -> Result<Vec<&'a str>, StoreError>;
