use crate::app::fixture;
use crate::harness::{init_logging, long_tempdir};
use crate::spool_refused::captured_log;
use crate::types::TestResult;
use agent_channel::agent_app::settle_events;
use agent_channel::client::deliver_events;
use agent_channel::error::ChannelError;
use agent_channel::proto::EventBatch;
use agent_channel::relay::{error_text, is_rate_refusal};
use agent_channel::spool::claim_spool;
use agent_channel::types::{DialFuture, PauseFuture};
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tonic::transport::Endpoint;
use tonic::{Code, Status};


const HOSTILE_MESSAGE_BYTES: usize = 14_000;


const MESSAGE_MARKER: &str = "WIRE-TAIL-MARKER";


const LOG_LINE_BOUND_BYTES: usize = 1024;


const ACCEPTED_CONNECTIONS: usize = 16;


async fn hostile_server(message: String) -> Result<SocketAddr, Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    tokio::spawn(async move {
        for _connection in 0..ACCEPTED_CONNECTIONS {
            if let Ok((stream, _peer)) = listener.accept().await {
                let text = message.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |_request| {
                        let answer = Status::new(Code::Internal, text.clone()).into_http::<tonic::body::Body>();
                        async move { Ok::<_, Infallible>(answer) }
                    });
                    if let Err(error) = Builder::new(TokioExecutor::new())
                        .http2_only()
                        .serve_connection(TokioIo::new(stream), service)
                        .await
                    {
                        tracing::debug!(%error, "hostile test connection ended");
                    }
                });
            }
        }
    });
    Ok(address)
}


fn batch(sequence: u64) -> EventBatch {
    EventBatch {
        sequence,
        ecs_json: b"{}".to_vec(),
        ..EventBatch::default()
    }
}


#[tokio::test]
async fn a_status_message_on_the_wire_is_bounded_in_the_event_delivery_failed_line() -> TestResult {
    init_logging()?;
    let (captured, _guard) = captured_log();
    let address = hostile_server(format!("{}{MESSAGE_MARKER}", "z".repeat(HOSTILE_MESSAGE_BYTES))).await?;
    let dial = move || -> DialFuture {
        Box::pin(async move {
            let channel = Endpoint::from_shared(format!("http://{address}"))
                .map_err(ChannelError::Transport)?
                .connect()
                .await?;
            Ok(channel)
        })
    };
    let pause = |_delay: Duration| -> PauseFuture { Box::pin(async {}) };
    let delivery = deliver_events(&dial, &pause, vec![batch(1)]).await;
    let delivered_error = delivery.as_ref().err().map(error_text).ok_or("delivery should have failed")?;
    assert!(delivered_error.contains("Internal"), "{delivered_error}");
    assert!(delivered_error.len() < LOG_LINE_BOUND_BYTES);
    assert!(!delivered_error.contains(MESSAGE_MARKER));
    let dir = long_tempdir()?;
    let agent = fixture(dir.path())?.agent;
    let spool = claim_spool(&agent)?;
    let events = settle_events(&agent, &spool, delivery)?;
    assert_eq!(events.failures, 1);
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("event delivery failed"), "{log}");
    assert!(!log.contains(MESSAGE_MARKER));
    assert!(log.lines().all(|line| line.len() < LOG_LINE_BOUND_BYTES));
    Ok(())
}


#[test]
fn a_rate_refusal_made_by_the_client_itself_is_not_a_server_answer() -> TestResult {
    let server_answer = ChannelError::Status(Box::new(Status::new(Code::ResourceExhausted, "slow down")));
    assert!(is_rate_refusal(&server_answer));
    let mut local = Status::new(Code::ResourceExhausted, "header list too large");
    local.set_source(Arc::new(std::io::Error::other("local goaway")));
    assert!(!is_rate_refusal(&ChannelError::Status(Box::new(local))));
    Ok(())
}


const INNER_ATTEMPTS: u32 = 2;


const OUTER_ATTEMPTS: u32 = 3;


const FORGED_MESSAGE: &str = "boom\nFORGED-LINE INFO agent all good\u{1b}[2J\u{7}";


#[tokio::test]
async fn control_characters_in_a_status_message_never_reach_the_log_raw() -> TestResult {
    init_logging()?;
    let (captured, _guard) = captured_log();
    let address = hostile_server(FORGED_MESSAGE.to_owned()).await?;
    let dial = move || -> DialFuture {
        Box::pin(async move {
            let channel = Endpoint::from_shared(format!("http://{address}"))
                .map_err(ChannelError::Transport)?
                .connect()
                .await?;
            Ok(channel)
        })
    };
    let pause = |_delay: Duration| -> PauseFuture { Box::pin(async {}) };
    let delivery = deliver_events(&dial, &pause, vec![batch(1)]).await;
    let dir = long_tempdir()?;
    let agent = fixture(dir.path())?.agent;
    let spool = claim_spool(&agent)?;
    settle_events(&agent, &spool, delivery)?;
    let log = String::from_utf8(captured.lock().map_err(|_| "poisoned")?.clone())?;
    assert!(log.contains("event delivery failed"), "{log}");
    assert!(log.contains("FORGED-LINE"), "{log}");
    assert!(!log.contains('\u{1b}') && !log.contains('\u{7}'), "{log:?}");
    assert!(log.lines().all(|line| !line.starts_with("FORGED-LINE")), "{log:?}");
    Ok(())
}


#[test]
fn a_nested_retries_exhausted_is_cut_to_its_count() -> TestResult {
    let inner = ChannelError::RetriesExhausted {
        attempts: INNER_ATTEMPTS,
        last: Box::new(ChannelError::Status(Box::new(Status::new(Code::Internal, "NESTED-MARKER")))),
    };
    let outer = ChannelError::RetriesExhausted {
        attempts: OUTER_ATTEMPTS,
        last: Box::new(inner),
    };
    let text = error_text(&outer);
    assert!(text.contains("abandoned after 3"), "{text}");
    assert!(text.contains("abandoned after 2"), "{text}");
    assert!(!text.contains("NESTED-MARKER"), "{text}");
    Ok(())
}
