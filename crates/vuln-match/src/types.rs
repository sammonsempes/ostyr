//! Type aliases.

use crate::model::UnmatchedReason;
use std::collections::BTreeMap;


pub type UnmatchedCounts = BTreeMap<UnmatchedReason, usize>;


pub type Archive = zip::ZipArchive<std::io::Cursor<Vec<u8>>>;
