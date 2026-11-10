use crate::memory::Entry;
use cases::model::Case;
use std::collections::BTreeMap;


pub type TestResult = Result<(), Box<dyn std::error::Error>>;


pub type Setter = fn(&mut Case, String);


pub type Table = BTreeMap<String, Entry>;
