pub type TestResult = Result<(), TestError>;


pub type TestError = Box<dyn std::error::Error>;
