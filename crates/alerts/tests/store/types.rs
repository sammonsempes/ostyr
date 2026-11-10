use alerts::model::Alert;
use alerts::types::Row;
use std::collections::BTreeMap;


pub type TestResult = Result<(), Box<dyn std::error::Error>>;


pub type Mutation = Box<dyn Fn(&mut Alert)>;


pub type Table = BTreeMap<String, (u64, Row)>;
