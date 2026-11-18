use cloud_cost::fetch_error::HttpFailure;
use cloud_cost::fetch_model::HttpResponse;
use std::error::Error;


pub type Reply = Result<HttpResponse, HttpFailure>;


pub type TestResult = Result<(), Box<dyn Error>>;
