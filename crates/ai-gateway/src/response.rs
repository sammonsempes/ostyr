use crate::error::AiError;
use crate::limits::{MAX_CHOICES, MAX_RESPONSE_NODES};
use crate::model::{Answer, FinishReason, HttpReply};
use crate::transport::body_error;
use serde::Deserialize;
use serde_json::value::RawValue;
use std::io::Read;


#[derive(Debug, Clone, Copy, Default)]
pub struct ScanState {
    pub in_string: bool,
    pub escaped: bool,
    pub weight: usize,
}


#[derive(Deserialize)]
pub struct Usage {
    #[serde(default)]
    pub prompt_tokens: Option<u32>,
    #[serde(default)]
    pub completion_tokens: Option<u32>,
}


#[derive(Deserialize)]
pub struct Completion<'a> {
    #[serde(borrow)]
    pub choices: Vec<&'a RawValue>,
    #[serde(default)]
    pub usage: Option<Usage>,
}


#[derive(Deserialize)]
pub struct Message {
    pub content: String,
}


#[derive(Deserialize)]
pub struct Choice {
    pub message: Message,
    #[serde(default)]
    pub finish_reason: Option<FinishReason>,
}


/// Counts arrays, objects and separators outside strings, so a body of tiny elements is refused before any element is materialised.
pub fn scan_byte(state: ScanState, byte: u8) -> Result<ScanState, AiError> {
    if state.in_string {
        Ok(ScanState {
            escaped: !state.escaped && byte == b'\\',
            in_string: state.escaped || byte != b'"',
            ..state
        })
    } else {
        match byte {
            b'"' => Ok(ScanState { in_string: true, ..state }),
            b'[' | b'{' | b',' if state.weight >= MAX_RESPONSE_NODES => Err(AiError::TooManyNodes { cap: MAX_RESPONSE_NODES }),
            b'[' | b'{' | b',' => Ok(ScanState {
                weight: state.weight + 1,
                ..state
            }),
            _ => Ok(state),
        }
    }
}


/// Category-free: line and column only, since serde's own text repeats the offending value, which is peer text.
pub fn malformed(error: serde_json::Error) -> AiError {
    AiError::Malformed {
        line: error.line(),
        column: error.column(),
    }
}


/// At most `cap + 1` bytes are read; over the cap is refused.
pub fn read_body(reply: HttpReply, cap: usize) -> Result<Vec<u8>, AiError> {
    let mut body = Vec::new();
    reply.body.take(cap as u64 + 1).read_to_end(&mut body).map_err(body_error)?;
    if body.len() > cap {
        Err(AiError::ResponseTooLarge { cap })
    } else {
        Ok(body)
    }
}


/// Pre-scan, then a typed parse: only the first choice's `message.content` and `finish_reason`, and `usage`, are read.
pub fn parse_answer(body: &[u8]) -> Result<Answer, AiError> {
    body.iter().try_fold(ScanState::default(), |state, byte| scan_byte(state, *byte))?;
    let completion: Completion = serde_json::from_slice(body).map_err(malformed)?;
    if completion.choices.len() > MAX_CHOICES {
        Err(AiError::TooManyChoices { cap: MAX_CHOICES })
    } else {
        let first = completion.choices.first().ok_or(AiError::NoChoice)?;
        let choice: Choice = serde_json::from_str(first.get()).map_err(malformed)?;
        Ok(Answer {
            content: choice.message.content,
            prompt_tokens: completion.usage.as_ref().and_then(|usage| usage.prompt_tokens),
            completion_tokens: completion.usage.as_ref().and_then(|usage| usage.completion_tokens),
            finish_reason: choice.finish_reason.unwrap_or(FinishReason::Other),
        })
    }
}
