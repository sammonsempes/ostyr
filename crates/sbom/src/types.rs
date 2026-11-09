//! Type aliases.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Take;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use struson::reader::JsonStreamReader;


pub type VersionsByKey<'a> = BTreeMap<&'a str, BTreeSet<&'a str>>;


pub type Reader<'a, Source> = JsonStreamReader<&'a mut Take<Source>>;


pub type Helpers = Arc<AtomicUsize>;
