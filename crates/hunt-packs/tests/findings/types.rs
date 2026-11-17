use hunt_packs::store::{FindingRow, Param};
use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;


pub type TestResult = Result<(), Box<dyn Error>>;


pub type Rows = Rc<RefCell<Vec<(String, FindingRow)>>>;


pub type Seen = Rc<RefCell<Vec<(String, &'static str, Vec<Param>)>>>;
