use std::collections::{BTreeMap, BTreeSet};
use std::time::Duration;


pub type MalformedCounts = BTreeMap<String, u64>;


pub type LeaseKey = (i64, i64, String, String, u32);


pub type SeenLeases = BTreeSet<LeaseKey>;


pub type FileIdentity = (u64, u64);


pub type PauseFn = fn(Duration);


pub type Label = (String, String);
