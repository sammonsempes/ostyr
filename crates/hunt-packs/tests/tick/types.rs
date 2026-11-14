use std::cell::RefCell;
use std::collections::HashMap;
use std::error::Error;
use std::rc::Rc;


pub type TestResult = Result<(), Box<dyn Error>>;


pub type Store = Rc<RefCell<HashMap<(String, String), i64>>>;


pub type Calls = Rc<RefCell<usize>>;
