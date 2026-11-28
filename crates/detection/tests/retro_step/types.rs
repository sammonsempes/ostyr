use detection::error::RetroError;
use detection::retro::RetroOutcome;
use std::error::Error;


pub type TestResult = Result<(), Box<dyn Error>>;


pub type ReadScript = Vec<Result<RetroOutcome, RetroError>>;
