pub type TestError = Box<dyn std::error::Error>;


pub type TestResult = Result<(), TestError>;


pub type Captured = std::sync::Arc<std::sync::Mutex<Vec<u8>>>;
