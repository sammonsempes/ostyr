pub type TestError = Box<dyn std::error::Error>;


pub type TestResult = Result<(), TestError>;


pub type Call = (String, Option<u32>, Option<i64>);
