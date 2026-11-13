use remote_desktop::model::RelayClaims;
use std::error::Error;


pub type TestResult = Result<(), Box<dyn Error>>;


pub type ClaimsChange = fn(&mut RelayClaims);


pub type RefusalCase = (&'static str, ClaimsChange, u64);
