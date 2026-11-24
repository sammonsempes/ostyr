use siem_ingest::model::AckAction;
use std::sync::{Arc, Mutex};


pub type Acks = Arc<Mutex<Vec<(u64, AckAction)>>>;


pub type Dead = Arc<Mutex<Vec<(String, Vec<u8>, String)>>>;


pub type Bodies = Arc<Mutex<Vec<String>>>;
