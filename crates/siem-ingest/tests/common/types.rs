use core_audit::model::NewEntry;
use std::error::Error;
use std::sync::{Arc, Mutex};


pub type TestResult = Result<(), Box<dyn Error>>;


pub type Batches = Arc<Mutex<Vec<usize>>>;


pub type Entries = Arc<Mutex<Vec<NewEntry>>>;
