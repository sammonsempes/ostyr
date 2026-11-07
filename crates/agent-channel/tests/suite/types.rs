use agent_channel::model::Identity;
use std::error::Error;
use std::sync::{Arc, Mutex};


pub type TestResult = Result<(), Box<dyn Error>>;


pub type Stored = Arc<Mutex<Vec<(Identity, u64)>>>;
