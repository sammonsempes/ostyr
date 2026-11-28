use agent_windows::error::RunError;
use agent_windows::model::{RunEnd, RunRequest};
use std::cell::RefCell;


pub type Runs = RefCell<Vec<(String, Vec<String>, Vec<(String, String)>, usize, u64)>>;


pub type Answer = Box<dyn FnMut(&RunRequest<'_>, &mut dyn FnMut(&[u8])) -> Result<RunEnd, RunError>>;
