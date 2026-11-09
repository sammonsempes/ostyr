//! Type aliases.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Take;
use struson::reader::JsonStreamReader;


pub type VersionsByKey<'a> = BTreeMap<&'a str, BTreeSet<&'a str>>;


pub type Reader<'a, Source> = JsonStreamReader<&'a mut Take<Source>>;
