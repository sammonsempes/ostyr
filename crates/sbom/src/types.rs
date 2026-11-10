//! Type aliases.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Take;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use struson::reader::JsonStreamReader;


pub type VersionsByKey<'a> = BTreeMap<&'a str, BTreeSet<&'a str>>;


pub type Reader<'a, Source> = JsonStreamReader<&'a mut Take<Source>>;


pub type Helpers = Arc<AtomicUsize>;


#[cfg(unix)]
pub type Job = Box<dyn FnOnce() -> Result<(), crate::error::RunError> + Send + 'static>;


pub type BoxError = Box<dyn std::error::Error + Send + Sync>;


pub type SignerFn = dyn Fn(&[u8]) -> Result<Vec<u8>, BoxError> + Send + Sync;


pub type TrustedKeys = BTreeMap<String, crate::model::TrustedKey>;


pub type DeadlineFn = fn(&std::path::Path) -> bool;
