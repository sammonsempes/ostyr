//! Type aliases.

use std::collections::{BTreeMap, BTreeSet};


pub type VersionsByKey<'a> = BTreeMap<&'a str, BTreeSet<&'a str>>;
