pub type TestError = Box<dyn std::error::Error>;


pub type TestResult = Result<(), TestError>;


pub type Statement = (String, &'static str, Vec<String>);
