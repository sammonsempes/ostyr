use std::error::Error;


pub type TestResult = Result<(), Box<dyn Error>>;


pub type Requests = Vec<Vec<String>>;
