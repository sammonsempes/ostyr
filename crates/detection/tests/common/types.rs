use std::collections::BTreeMap;
use std::error::Error;
use std::sync::{Arc, Mutex};


pub type TestResult = Result<(), Box<dyn Error + Send + Sync>>;


pub type Tables = Arc<Mutex<BTreeMap<String, Vec<String>>>>;
