//! Type aliases.

use crate::model::{SkipReason, WindowsSkip, WindowsUpdate};
use std::collections::BTreeMap;


pub type SkipCounts = BTreeMap<SkipReason, usize>;


pub type UpdateKey = (String, String);


pub type WindowsSkipCounts = BTreeMap<WindowsSkip, usize>;


pub type UpdatesById = BTreeMap<String, WindowsUpdate>;
