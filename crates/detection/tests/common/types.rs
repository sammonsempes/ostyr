use std::collections::{BTreeMap, VecDeque};
use std::error::Error;
use std::sync::{Arc, Mutex};


pub type TestResult = Result<(), Box<dyn Error + Send + Sync>>;


pub type Tables = Arc<Mutex<BTreeMap<String, Vec<String>>>>;


pub type Script = Arc<Mutex<VecDeque<&'static str>>>;


pub type MigrateRefusal = Arc<Mutex<Option<&'static str>>>;
