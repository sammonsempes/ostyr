pub type TestError = Box<dyn std::error::Error>;


pub type TestResult = Result<(), TestError>;


pub type Calls = std::sync::Arc<std::sync::Mutex<Vec<String>>>;
