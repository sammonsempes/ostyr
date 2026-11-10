use std::error::Error;


pub type TestError = Box<dyn Error>;


pub type TestResult = Result<(), TestError>;
