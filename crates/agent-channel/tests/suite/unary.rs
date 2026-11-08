use crate::harness::{bounded, scoped_logging};
use crate::types::TestResult;
use agent_channel::client::{heartbeat, report_command};
use agent_channel::error::ChannelError;
use agent_channel::model::{CommandVerdict, PLACEHOLDER_ENDPOINT, UNARY_TIMEOUT_SECONDS};
use axum::body::Body;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tonic::transport::{Channel, Endpoint};
use tower::service_fn;


const LONG_WAIT_SECONDS: u64 = 600;


async fn silent_server() -> Result<(SocketAddr, JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        match listener.accept().await {
            Ok((tcp, _peer)) => {
                let silent = service_fn(|_request: http::Request<hyper::body::Incoming>| async {
                    std::future::pending::<Result<http::Response<Body>, Infallible>>().await
                });
                let served = Builder::new(TokioExecutor::new())
                    .http2_only()
                    .serve_connection(TokioIo::new(tcp), TowerToHyperService::new(silent))
                    .await;
                tracing::debug!(?served, "silent server connection ended");
            }
            Err(error) => tracing::warn!(%error, "silent server accept failed"),
        }
    });
    Ok((address, handle))
}


async fn dial(address: SocketAddr) -> Result<Channel, Box<dyn std::error::Error>> {
    let channel = Endpoint::from_static(PLACEHOLDER_ENDPOINT)
        .connect_with_connector(service_fn(move |_uri: http::Uri| async move {
            TcpStream::connect(address).await.map(TokioIo::new)
        }))
        .await?;
    Ok(channel)
}


#[tokio::test]
async fn a_server_that_never_answers_a_heartbeat_hits_the_deadline() -> TestResult {
    let _logging = scoped_logging();
    let (address, server) = silent_server().await?;
    let channel = bounded(dial(address)).await??;
    tokio::time::pause();
    let outcome = timeout(Duration::from_secs(LONG_WAIT_SECONDS), heartbeat(channel, "test")).await?;
    assert!(matches!(outcome, Err(ChannelError::CallTimedOut { seconds }) if seconds == UNARY_TIMEOUT_SECONDS));
    server.abort();
    Ok(())
}


#[tokio::test]
async fn a_server_that_never_answers_a_report_hits_the_deadline() -> TestResult {
    let _logging = scoped_logging();
    let (address, server) = silent_server().await?;
    let channel = bounded(dial(address)).await??;
    let verdict = CommandVerdict {
        digest: Vec::new(),
        accepted: true,
        reason: String::new(),
    };
    tokio::time::pause();
    let outcome = timeout(Duration::from_secs(LONG_WAIT_SECONDS), report_command(channel, &verdict)).await?;
    assert!(matches!(outcome, Err(ChannelError::CallTimedOut { .. })));
    server.abort();
    Ok(())
}
