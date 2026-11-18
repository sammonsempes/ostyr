use crate::numbers::{COMPLETION_TOKENS, PROMPT_TOKENS};
use ai_gateway::error::AiError;
use ai_gateway::limits::{DEFAULT_MAX_REQUEST_BYTES, DEFAULT_MAX_RESPONSE_BYTES, ENDPOINT_PATH, MAX_RESPONSE_NODES, STATUS_OK};
use ai_gateway::model::{Deps, HttpReply, HttpRequest};
use ai_gateway::settings::AiSettings;
use serde_json::{json, Value};
use std::error::Error;
use std::io::{Cursor, Read};


pub const MARKER: &str = "peer-marker-7f3a";


pub const TIMEOUT: u64 = 5;


pub const TOKENS: u32 = 256;


pub const FILL_BYTE: u8 = 0xab;


pub const FIXED_NONCE: &str = "abababababababababababababababab";


pub const FIXED_CLOCK: u64 = 7;


pub const BIG_BODY_BYTES: usize = 1_024 * 1_024;


pub const HUGE_BODY_BYTES: usize = 2 * 1_024 * 1_024;


pub const STATUS_UNAUTHORIZED: u16 = 401;


pub const STATUS_TOO_MANY: u16 = 429;


pub const STATUS_SERVER: u16 = 500;


pub const NINE: usize = 9;


pub const KEY_COUNT: usize = 50_000;


pub const CHOICE_COUNT: usize = 20_000;


pub fn settings(script: &str) -> AiSettings {
    AiSettings {
        base_url: format!("https://model.example/{script}"),
        model: "test-model:1".to_owned(),
        api_key_file: None,
        ca_file: None,
        timeout_seconds: TIMEOUT,
        max_tokens: TOKENS,
        max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
        max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
    }
}


pub fn fixed_random(buffer: &mut [u8]) -> Result<(), AiError> {
    buffer.fill(FILL_BYTE);
    Ok(())
}


pub fn fixed_clock() -> u64 {
    FIXED_CLOCK
}


pub fn deps(transport: ai_gateway::types::TransportFn) -> Deps {
    Deps {
        transport,
        random: fixed_random,
        clock: fixed_clock,
    }
}


pub fn real_random_deps(transport: ai_gateway::types::TransportFn) -> Deps {
    Deps {
        random: ai_gateway::chat::os_random,
        ..deps(transport)
    }
}


pub fn reply(status: u16, bytes: Vec<u8>) -> Result<HttpReply, AiError> {
    Ok(HttpReply {
        status,
        body: Box::new(Cursor::new(bytes)),
    })
}


pub fn completion(content: &str) -> Vec<u8> {
    json!({"choices": [{"message": {"role": "assistant", "content": content}, "finish_reason": "stop"}], "usage": {"prompt_tokens": PROMPT_TOKENS, "completion_tokens": COMPLETION_TOKENS}})
        .to_string()
        .into_bytes()
}


pub fn script_name(url: &str) -> &str {
    url.strip_suffix(ENDPOINT_PATH).and_then(|base| base.rsplit('/').next()).unwrap_or("")
}


pub fn answer_with(choices: &Value) -> Vec<u8> {
    json!({"choices": choices}).to_string().into_bytes()
}


pub struct Failing;


impl Read for Failing {
    fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other(MARKER))
    }
}


pub fn many_keys() -> String {
    format!(
        "{{\"choices\":[{{\"message\":{{\"content\":\"x\"}}}}],\"usage\":{{{}}}}}",
        (0..KEY_COUNT).map(|index| format!("\"k{index}\":1")).collect::<Vec<_>>().join(",")
    )
}


pub fn many_choices() -> Value {
    Value::Array((0..CHOICE_COUNT).map(|_index| json!({"message": {"content": "x"}})).collect())
}


/// A fake model endpoint: the last path segment of the base URL picks the behaviour.
pub fn scripted(request: &HttpRequest) -> Result<HttpReply, AiError> {
    match script_name(&request.url) {
        "echo" => reply(STATUS_OK, completion(&String::from_utf8_lossy(&request.body))),
        "auth" => reply(
            STATUS_OK,
            completion(request.authorization.as_ref().map_or("none", |value| value.as_str())),
        ),
        "ok" => reply(STATUS_OK, completion("hello")),
        "401" => reply(STATUS_UNAUTHORIZED, MARKER.as_bytes().to_vec()),
        "429" => reply(STATUS_TOO_MANY, MARKER.as_bytes().to_vec()),
        "500" => reply(STATUS_SERVER, MARKER.as_bytes().to_vec()),
        "nested" => reply(STATUS_OK, "[".repeat(BIG_BODY_BYTES).into_bytes()),
        "huge" => reply(STATUS_OK, vec![b' '; HUGE_BODY_BYTES]),
        "keys" => reply(STATUS_OK, many_keys().into_bytes()),
        "manychoices" => reply(STATUS_OK, answer_with(&many_choices())),
        "nine" => reply(
            STATUS_OK,
            answer_with(&Value::Array((0..NINE).map(|_index| json!({"message": {"content": "x"}})).collect())),
        ),
        "none" => reply(STATUS_OK, answer_with(&json!([]))),
        "number" => reply(STATUS_OK, answer_with(&json!([{"message": {"content": true}}]))),
        "null" => reply(STATUS_OK, answer_with(&json!([{"message": {"content": null}}]))),
        "missing" => reply(STATUS_OK, answer_with(&json!([{"message": {}}]))),
        "nomessage" => reply(STATUS_OK, answer_with(&json!([{}]))),
        "length" => reply(
            STATUS_OK,
            answer_with(&json!([{"message": {"content": "cut"}, "finish_reason": "length"}])),
        ),
        "weird" => reply(
            STATUS_OK,
            answer_with(&json!([{"message": {"content": "w"}, "finish_reason": "tool_calls"}])),
        ),
        "nofinish" => reply(STATUS_OK, answer_with(&json!([{"message": {"content": "n"}}]))),
        "nullfinish" => reply(STATUS_OK, answer_with(&json!([{"message": {"content": "n"}, "finish_reason": null}]))),
        "badusage" => reply(
            STATUS_OK,
            json!({"choices": [{"message": {"content": "x"}}], "usage": MARKER})
                .to_string()
                .into_bytes(),
        ),
        "notjson" => reply(STATUS_OK, format!("{{\"choices\": {MARKER}").into_bytes()),
        "broken" => Ok(HttpReply {
            status: STATUS_OK,
            body: Box::new(Failing),
        }),
        "transport" => Err(AiError::Protocol),
        _ => Err(AiError::Connect),
    }
}


pub fn chain(error: &(dyn Error + 'static)) -> String {
    std::iter::successors(Some(error), |inner| (*inner).source())
        .map(|inner| format!("{inner} {inner:?}"))
        .collect::<Vec<_>>()
        .join(" | ")
}


pub const NODE_CAP: usize = MAX_RESPONSE_NODES;
