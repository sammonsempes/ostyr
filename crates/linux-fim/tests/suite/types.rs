use std::error::Error;


pub type TestResult = Result<(), Box<dyn Error>>;


pub type ResolvedArgs = Vec<(u32, String, String)>;
