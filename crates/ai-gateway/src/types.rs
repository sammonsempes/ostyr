use crate::error::AiError;
use crate::model::{HttpReply, HttpRequest};


pub type TransportFn = fn(&HttpRequest) -> Result<HttpReply, AiError>;


pub type RandomFn = fn(&mut [u8]) -> Result<(), AiError>;


pub type ClockFn = fn() -> u64;
