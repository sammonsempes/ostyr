use std::error::Error;


pub type SoftResult<Value> = Result<Value, Box<dyn Error>>;
