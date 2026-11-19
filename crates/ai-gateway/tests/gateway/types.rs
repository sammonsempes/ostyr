use ai_gateway::budget::Param;
use std::error::Error;


pub type TestResult = Result<(), Box<dyn Error>>;


pub type Statements = Vec<(String, &'static str, Vec<Param>)>;
