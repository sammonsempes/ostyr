use std::error::Error;


pub type TestResult = Result<(), TestError>;


pub type TestError = Box<dyn Error>;
