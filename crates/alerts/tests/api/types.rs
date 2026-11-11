use alerts::types::Row;
use std::collections::BTreeMap;


pub type TestError = Box<dyn std::error::Error>;


pub type TestResult = Result<(), TestError>;


pub type Table = BTreeMap<String, (u64, Row)>;


pub type TriageKey = (String, String);


pub type TriageRow = (String, String, String, u64, i64);
