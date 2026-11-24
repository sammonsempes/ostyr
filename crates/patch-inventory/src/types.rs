//! Type aliases.

use crate::limits::ROW_CELL_COUNT;
use crate::model::{SkipReason, Update, WindowsSkip, WindowsUpdate, WingetSkip};
use std::collections::BTreeMap;


pub type SkipCounts = BTreeMap<SkipReason, usize>;


pub type UpdateKey = (String, String);


pub type WindowsSkipCounts = BTreeMap<WindowsSkip, usize>;


pub type UpdatesById = BTreeMap<String, WindowsUpdate>;


pub type WingetSkipCounts = BTreeMap<WingetSkip, usize>;


pub type UpdatesByPackage = BTreeMap<String, Update>;


pub type RowCells<'a> = [&'a str; ROW_CELL_COUNT];
