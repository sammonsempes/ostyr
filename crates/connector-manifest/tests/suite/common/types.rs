use std::error::Error;


#[cfg(target_os = "linux")]
pub type Failure = Box<dyn Error>;


pub type TestResult = Result<(), Box<dyn Error>>;
