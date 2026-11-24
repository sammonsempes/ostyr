pub type Failure = Box<dyn std::error::Error>;


pub type TestResult = Result<(), Failure>;
