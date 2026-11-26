use detection::error::RetroError;
use detection::retro::{RetroOutcome, RetroReply, RetroRequest};
use siem_ingest::error::InsertClass;
use std::collections::VecDeque;
use std::error::Error;


pub type TestResult = Result<(), Box<dyn Error>>;


pub type Scripted = VecDeque<Result<RetroReply, InsertClass>>;


pub type Run = (Result<RetroOutcome, RetroError>, Vec<RetroRequest>);
