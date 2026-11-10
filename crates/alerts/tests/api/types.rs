use alerts::types::Row;
use std::collections::BTreeMap;


pub type TestError = Box<dyn std::error::Error>;


pub type TestResult = Result<(), TestError>;


pub type Table = BTreeMap<String, (u64, Row)>;
