use crate::types::{ClockFn, RandomFn, TransportFn};
use serde::Deserialize;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;


/// What goes on the wire. `authorization` is the whole header value, zeroed on drop; the struct has no `Debug`, so the key cannot be printed.
pub struct HttpRequest {
    pub url: String,
    pub authorization: Option<Zeroizing<String>>,
    pub body: Vec<u8>,
    pub timeout: Duration,
    pub ca_file: Option<PathBuf>,
}


pub struct HttpReply {
    pub status: u16,
    pub body: Box<dyn Read>,
}


/// The three injected dependencies; production values come from `production_deps`.
#[derive(Clone, Copy)]
pub struct Deps {
    pub transport: TransportFn,
    pub random: RandomFn,
    pub clock: ClockFn,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FinishReason {
    Stop,
    Length,
    #[serde(other)]
    Other,
}


/// `content` is untrusted text from the model: the caller never treats it as an instruction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Answer {
    pub content: String,
    pub prompt_tokens: Option<u32>,
    pub completion_tokens: Option<u32>,
    pub finish_reason: FinishReason,
}
