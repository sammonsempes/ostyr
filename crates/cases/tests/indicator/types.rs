pub type TestResult = Result<(), TestError>;


pub type TestError = Box<dyn std::error::Error>;


pub type Call = (String, &'static str, Vec<String>);
