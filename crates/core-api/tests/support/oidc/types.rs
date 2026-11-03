use std::sync::{Arc, Mutex};


pub type TokenCell = Arc<Mutex<Option<String>>>;
