use rustls::{ServerConfig, ServerConnection, StreamOwned};
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::thread::spawn;
use std::time::Duration;
use tracing::debug;


pub const TERMINATOR_LEN: usize = 2;


pub const PUB_WITH_REPLY: usize = 4;


pub const HPUB_WITH_REPLY: usize = 5;


pub const REPLY_POSITION: usize = 2;


pub const API_ERROR_CODE: u32 = 500;


pub const API_ERROR_ID: u32 = 10_000;


pub const PUBLISH_ERROR_CODE: u32 = 503;


pub const PUBLISH_ERROR_ID: u32 = 10_077;


pub const MAX_FRAMES: usize = 1_000_000;


pub const DEFAULT_MAX_PAYLOAD: usize = 1_048_576;


pub const WAIT_SECONDS: u64 = 20;


pub const CREATE_MARKER: &str = ".CREATE.";


pub const PULL_PREFIX: &str = "$JS.API.CONSUMER.MSG.NEXT.";


pub const ACK_PREFIX: &str = "$JS.ACK.";


pub const DEAD_SUBJECT: &str = "dead.events";


pub const EVENTS_PREFIX: &str = "events.";


pub const API_PREFIX: &str = "$JS.API.CONSUMER.";


pub struct Queued {
    pub subject: String,
    pub payload: Vec<u8>,
    pub extra_headers: usize,
    pub repeated_values: usize,
}


pub struct Published {
    pub subject: String,
    pub headers: String,
    pub payload: Vec<u8>,
}


pub struct Outgoing {
    pub target: String,
    pub subject: Option<String>,
    pub ack_reply: Option<String>,
    pub headers: Option<String>,
    pub payload: Vec<u8>,
}


#[derive(Default)]
pub struct StubState {
    pub acks: Vec<String>,
    pub published: Vec<Published>,
    pub creates: Vec<Value>,
    pub pulls: Vec<Value>,
    pub queue: VecDeque<Queued>,
    pub connects: Vec<Value>,
    pub connections: usize,
    pub sockets: Vec<TcpStream>,
    pub fail_create: bool,
    pub silent_pull: bool,
    pub pull_status: Option<String>,
    pub fail_publish: bool,
    pub silent_publish: bool,
    pub max_payload: usize,
    pub nonce: bool,
    pub delivered: u64,
}


#[derive(Default)]
pub struct Hub {
    pub state: Mutex<StubState>,
    pub changed: Condvar,
}


pub struct Stub {
    pub port: u16,
    pub hub: Arc<Hub>,
}


pub fn lock(hub: &Hub) -> MutexGuard<'_, StubState> {
    hub.state.lock().unwrap_or_else(PoisonError::into_inner)
}


pub fn report(outcome: io::Result<()>) {
    if let Err(error) = outcome {
        debug!(%error, "stub connection ended");
    }
}


pub fn start_stub(tls: Option<Arc<ServerConfig>>, configure: impl FnOnce(&mut StubState)) -> io::Result<Stub> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let hub = Arc::new(Hub::default());
    {
        let mut state = lock(&hub);
        state.max_payload = DEFAULT_MAX_PAYLOAD;
        configure(&mut state);
    }
    let accept_hub = Arc::clone(&hub);
    spawn(move || {
        listener.incoming().for_each(|accepted| {
            let hub_for_connection = Arc::clone(&accept_hub);
            let tls_for_connection = tls.clone();
            report(accepted.map(|stream| {
                spawn(move || report(serve_stream(stream, &hub_for_connection, tls_for_connection)));
            }));
        });
    });
    Ok(Stub { port, hub })
}


pub fn serve_stream(stream: TcpStream, hub: &Hub, tls: Option<Arc<ServerConfig>>) -> io::Result<()> {
    {
        let mut state = lock(hub);
        state.connections += 1;
        state.sockets.push(stream.try_clone()?);
    }
    hub.changed.notify_all();
    match tls {
        Some(config) => serve(StreamOwned::new(ServerConnection::new(config).map_err(io::Error::other)?, stream), hub),
        None => serve(stream, hub),
    }
}


pub fn write_all<Stream: Write>(reader: &mut BufReader<Stream>, bytes: &[u8]) -> io::Result<()> {
    let writer = reader.get_mut();
    writer.write_all(bytes)?;
    writer.flush()
}


pub fn serve<Stream: Read + Write>(stream: Stream, hub: &Hub) -> io::Result<()> {
    let mut reader = BufReader::new(stream);
    let info = {
        let state = lock(hub);
        json!({
            "server_id": "stub", "server_name": "stub", "version": "2.10.0", "proto": 1, "headers": true,
            "max_payload": state.max_payload, "jetstream": true, "auth_required": state.nonce,
            "nonce": if state.nonce { "stubnonce" } else { "" },
        })
    };
    write_all(&mut reader, format!("INFO {info}\r\n").as_bytes())?;
    let mut subscriptions: Vec<(String, String)> = Vec::new();
    (0..MAX_FRAMES).try_for_each(|_| step(&mut reader, hub, &mut subscriptions))
}


pub fn read_line<Stream: Read>(reader: &mut BufReader<Stream>) -> io::Result<String> {
    let mut line = String::new();
    if reader.read_line(&mut line)? == 0 {
        Err(io::ErrorKind::UnexpectedEof.into())
    } else {
        Ok(line.trim_end().to_owned())
    }
}


pub fn read_body<Stream: Read>(reader: &mut BufReader<Stream>, size: usize) -> io::Result<Vec<u8>> {
    let mut body = vec![0; size + TERMINATOR_LEN];
    reader.read_exact(&mut body)?;
    body.truncate(size);
    Ok(body)
}


pub fn part<'a>(parts: &[&'a str], index: usize) -> io::Result<&'a str> {
    parts.get(index).copied().ok_or_else(|| io::Error::other("short frame"))
}


pub fn number_from_end(parts: &[&str], position: usize) -> io::Result<usize> {
    parts
        .iter()
        .rev()
        .nth(position)
        .ok_or_else(|| io::Error::other("short frame"))?
        .parse()
        .map_err(io::Error::other)
}


pub fn step<Stream: Read + Write>(reader: &mut BufReader<Stream>, hub: &Hub, subscriptions: &mut Vec<(String, String)>) -> io::Result<()> {
    let line = read_line(reader)?;
    let parts: Vec<&str> = line.split(' ').collect();
    match part(&parts, 0)? {
        "CONNECT" => {
            let connect: Value = serde_json::from_str(line.trim_start_matches("CONNECT ")).map_err(io::Error::other)?;
            lock(hub).connects.push(connect);
            hub.changed.notify_all();
            Ok(())
        }
        "PING" => write_all(reader, b"PONG\r\n"),
        "SUB" => {
            subscriptions.push((part(&parts, 1)?.to_owned(), part(&parts, parts.len() - 1)?.to_owned()));
            Ok(())
        }
        "PUB" => {
            let size = number_from_end(&parts, 0)?;
            let body = read_body(reader, size)?;
            let reply = (parts.len() == PUB_WITH_REPLY).then(|| part(&parts, REPLY_POSITION)).transpose()?;
            dispatch(reader, hub, subscriptions, (part(&parts, 1)?, reply), (String::new(), body))
        }
        "HPUB" => {
            let total = number_from_end(&parts, 0)?;
            let header_size = number_from_end(&parts, 1)?;
            let body = read_body(reader, total)?;
            let (head, payload) = body.split_at_checked(header_size).ok_or_else(|| io::Error::other("short body"))?;
            let reply = (parts.len() == HPUB_WITH_REPLY).then(|| part(&parts, REPLY_POSITION)).transpose()?;
            let headers = String::from_utf8_lossy(head).into_owned();
            dispatch(reader, hub, subscriptions, (part(&parts, 1)?, reply), (headers, payload.to_vec()))
        }
        _ => Ok(()),
    }
}


pub fn matches(pattern: &str, subject: &str) -> bool {
    let pattern_tokens: Vec<&str> = pattern.split('.').collect();
    let subject_tokens: Vec<&str> = subject.split('.').collect();
    let same = |(left, right): (&&str, &&str)| *left == "*" || left == right;
    let tail = pattern_tokens.last() == Some(&">") && subject_tokens.len() >= pattern_tokens.len();
    let prefix_len = pattern_tokens.len() - 1;
    (tail && pattern_tokens.iter().zip(&subject_tokens).take(prefix_len).all(same))
        || (pattern_tokens.len() == subject_tokens.len() && pattern_tokens.iter().zip(&subject_tokens).all(same))
}


pub fn frame(out: &Outgoing, sid: &str) -> Vec<u8> {
    let subject = out.subject.as_deref().unwrap_or(&out.target);
    let reply = out.ack_reply.as_deref().map_or(String::new(), |text| format!("{text} "));
    let mut bytes = match &out.headers {
        Some(headers) => format!(
            "HMSG {subject} {sid} {reply}{} {}\r\n{headers}",
            headers.len(),
            headers.len() + out.payload.len()
        )
        .into_bytes(),
        None => format!("MSG {subject} {sid} {reply}{}\r\n", out.payload.len()).into_bytes(),
    };
    bytes.extend_from_slice(&out.payload);
    bytes.extend_from_slice(b"\r\n");
    bytes
}


pub fn status(code: &str) -> String {
    format!("NATS/1.0 {code}\r\n\r\n")
}


pub fn plain_reply(reply: Option<&str>, payload: Value) -> Vec<Outgoing> {
    reply
        .into_iter()
        .map(|target| Outgoing {
            target: target.to_owned(),
            subject: None,
            ack_reply: None,
            headers: None,
            payload: payload.to_string().into_bytes(),
        })
        .collect()
}


pub fn create_reply(state: &mut StubState, subject: &str, reply: Option<&str>, payload: &[u8]) -> io::Result<Vec<Outgoing>> {
    let request: Value = serde_json::from_slice(payload).map_err(io::Error::other)?;
    state.creates.push(json!({"subject": subject, "request": request}));
    let config = request.get("config").cloned().unwrap_or(Value::Null);
    let name = config.get("durable_name").cloned().unwrap_or(Value::Null);
    let stream = request.get("stream_name").cloned().unwrap_or(Value::Null);
    let sequences = json!({"consumer_seq": 0, "stream_seq": 0});
    Ok(plain_reply(
        reply,
        if state.fail_create {
            json!({"error": {"code": API_ERROR_CODE, "err_code": API_ERROR_ID, "description": "stub refuses"}})
        } else {
            json!({
                "type": "io.nats.jetstream.api.v1.consumer_create_response", "stream_name": stream, "name": name,
                "created": "2026-01-01T00:00:00Z", "config": config, "delivered": sequences, "ack_floor": sequences,
                "num_ack_pending": 0, "num_redelivered": 0, "num_waiting": 0, "num_pending": 0,
            })
        },
    ))
}


pub fn queued_message(state: &mut StubState, queued: Queued, inbox: &str) -> Outgoing {
    state.delivered += 1;
    let distinct: String = (0..queued.extra_headers).map(|index| format!("X-{index}: v\r\n")).collect();
    let repeated: String = (0..queued.repeated_values).map(|index| format!("X-Same: v{index}\r\n")).collect();
    let extra = format!("{distinct}{repeated}");
    Outgoing {
        target: inbox.to_owned(),
        subject: Some(queued.subject),
        ack_reply: Some(format!("$JS.ACK.events.siem-ingest.1.{0}.{0}.0.0", state.delivered)),
        headers: (!extra.is_empty()).then(|| format!("NATS/1.0\r\n{extra}\r\n")),
        payload: queued.payload,
    }
}


pub fn pull_reply(state: &mut StubState, reply: Option<&str>, payload: &[u8]) -> io::Result<Vec<Outgoing>> {
    let request: Value = serde_json::from_slice(payload).map_err(io::Error::other)?;
    let wanted = request.get("batch").and_then(Value::as_u64).unwrap_or(0) as usize;
    state.pulls.push(request);
    let inbox = reply.unwrap_or("");
    if state.silent_pull {
        Ok(Vec::new())
    } else if let Some(code) = state.pull_status.clone() {
        Ok(vec![status_message(inbox, &code)])
    } else {
        let count = wanted.min(state.queue.len());
        let taken: Vec<Queued> = state.queue.drain(..count).collect();
        let mut out: Vec<Outgoing> = taken.into_iter().map(|queued| queued_message(state, queued, inbox)).collect();
        if count < wanted {
            out.push(status_message(inbox, "408 Request Timeout"));
        }
        Ok(out)
    }
}


pub fn status_message(inbox: &str, code: &str) -> Outgoing {
    Outgoing {
        target: inbox.to_owned(),
        subject: None,
        ack_reply: None,
        headers: Some(status(code)),
        payload: Vec::new(),
    }
}


pub fn route(state: &mut StubState, subject: &str, reply: Option<&str>, headers: &str, payload: &[u8]) -> io::Result<Vec<Outgoing>> {
    if subject.starts_with(API_PREFIX) && subject.contains(CREATE_MARKER) {
        create_reply(state, subject, reply, payload)
    } else if subject.starts_with(PULL_PREFIX) {
        pull_reply(state, reply, payload)
    } else if subject.starts_with(ACK_PREFIX) {
        state.acks.push(if payload.is_empty() {
            "+ACK".to_owned()
        } else {
            String::from_utf8_lossy(payload).into_owned()
        });
        Ok(Vec::new())
    } else if subject == DEAD_SUBJECT || subject.starts_with(EVENTS_PREFIX) {
        state.published.push(Published {
            subject: subject.to_owned(),
            headers: headers.to_owned(),
            payload: payload.to_vec(),
        });
        Ok(if state.silent_publish {
            Vec::new()
        } else if state.fail_publish {
            plain_reply(
                reply,
                json!({"error": {"code": PUBLISH_ERROR_CODE, "err_code": PUBLISH_ERROR_ID, "description": "stub refuses"}}),
            )
        } else {
            plain_reply(reply, json!({"stream": "dead", "seq": state.published.len()}))
        })
    } else {
        Ok(Vec::new())
    }
}


pub fn dispatch<Stream: Read + Write>(
    reader: &mut BufReader<Stream>,
    hub: &Hub,
    subscriptions: &[(String, String)],
    (subject, reply): (&str, Option<&str>),
    (headers, payload): (String, Vec<u8>),
) -> io::Result<()> {
    let outgoing = route(&mut lock(hub), subject, reply, &headers, &payload)?;
    hub.changed.notify_all();
    outgoing.iter().try_for_each(|out| {
        subscriptions
            .iter()
            .filter(|(pattern, _)| matches(pattern, &out.target))
            .try_for_each(|(_, sid)| write_all(reader, &frame(out, sid)))
    })
}


pub fn wait_until(stub: &Stub, condition: impl Fn(&StubState) -> bool) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let guard = lock(&stub.hub);
    let (_released, outcome) = stub
        .hub
        .changed
        .wait_timeout_while(guard, Duration::from_secs(WAIT_SECONDS), |state| !condition(state))
        .map_err(|_| "poisoned")?;
    if outcome.timed_out() {
        Err("the stub condition was not reached".into())
    } else {
        Ok(())
    }
}


pub fn kill_connections(stub: &Stub) {
    lock(&stub.hub).sockets.drain(..).for_each(|socket| {
        if let Err(error) = socket.shutdown(Shutdown::Both) {
            debug!(%error, "stub socket already closed");
        }
    });
}
