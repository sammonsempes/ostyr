use crate::api::{Answer, Seen};
use std::sync::{Arc, Mutex};


pub type Handler = Arc<dyn Fn(&Seen) -> Answer + Send + Sync>;


pub type Log = Arc<Mutex<Vec<Seen>>>;
