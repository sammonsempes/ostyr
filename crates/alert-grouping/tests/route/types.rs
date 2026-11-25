use alerts::types::ListFn;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;


pub type TestError = Box<dyn std::error::Error>;


pub type TestResult = Result<(), TestError>;


pub type Served = (ListFn, Arc<AtomicUsize>);
