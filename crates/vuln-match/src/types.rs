//! Type aliases.

use crate::model::UnmatchedReason;
use std::collections::BTreeMap;


pub type UnmatchedCounts = BTreeMap<UnmatchedReason, usize>;


pub type Archive<'a> = zip::ZipArchive<std::io::Cursor<&'a [u8]>>;
