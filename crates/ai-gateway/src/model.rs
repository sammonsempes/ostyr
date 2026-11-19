use crate::types::{ClockFn, RandomFn, TransportFn};
use serde::Deserialize;
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;


/// What goes on the wire. `authorization` is the whole header value, zeroed on drop; the struct has no `Debug`, so the key cannot be printed.
pub struct HttpRequest {
    pub(crate) url: String,
    pub(crate) authorization: Option<Zeroizing<String>>,
    pub(crate) body: Vec<u8>,
    pub(crate) timeout: Duration,
    pub(crate) ca_file: Option<PathBuf>,
}


pub fn request_url(request: &HttpRequest) -> &str {
    request.url.as_str()
}


pub fn request_body(request: &HttpRequest) -> &[u8] {
    request.body.as_slice()
}


pub fn request_authorization(request: &HttpRequest) -> Option<&str> {
    request.authorization.as_ref().map(|value| value.as_str())
}


pub struct HttpReply {
    pub status: u16,
    pub body: Box<dyn Read>,
}


/// The three injected dependencies; production values come from `production_deps`.
#[derive(Clone, Copy)]
pub struct Deps {
    pub(crate) transport: TransportFn,
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
