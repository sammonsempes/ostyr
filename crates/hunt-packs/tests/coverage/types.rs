use core_pg::error::PgError;
use hunt_packs::coverage::{FindingsRow, RunRow};
use hunt_packs::store::Param;
use std::cell::RefCell;
use std::error::Error;
use std::rc::Rc;


pub type TestResult = Result<(), Box<dyn Error>>;


pub type Calls = Rc<RefCell<Vec<(String, &'static str, Vec<Param>)>>>;


pub type RunsAnswer = Result<Vec<RunRow>, PgError>;


pub type FindingsAnswer = Result<Vec<FindingsRow>, PgError>;
