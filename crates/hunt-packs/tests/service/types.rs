use crate::Rig;
use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::io;
use std::rc::Rc;
use std::sync::{Arc, Mutex};


pub type TestResult = Result<(), Box<dyn Error>>;


pub type RunLog = Rc<RefCell<Vec<(String, String, i64)>>>;


pub type Audited = Arc<Mutex<Vec<String>>>;


pub type Store = RefCell<HashMap<(String, String), i64>>;


pub type OnSleep<'hook> = dyn FnMut(usize, &Rig) -> io::Result<()> + 'hook;
