pub type TestError = Box<dyn std::error::Error>;


pub type TestResult = Result<(), TestError>;
