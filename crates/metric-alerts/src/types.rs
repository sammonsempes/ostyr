use std::collections::BTreeMap;


pub type Timestamp = u64;


pub type Point = (Timestamp, f64);


pub type Labels = BTreeMap<String, String>;


pub type QueryParams = Vec<(String, String)>;
