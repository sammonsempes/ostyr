use crate::harness::{
    attempt, attempt_with, bounded, client_paths, custom_client, empty_revocation, finish, init_logging, make_platform, server_paths, start_server,
    start_single, stop_server,
};
use crate::pki::{agent_spec, make_authority, LeafSpec, AGENT_URI};
use crate::types::TestResult;
use agent_channel::client::{connect_channel, heartbeat};
use agent_channel::error::{ChannelError, IdentityError};
use agent_channel::model::Identity;
use agent_channel::proto::BeatRequest;
use agent_channel::server::{beat, channel_router, log_outcome, serve};
use agent_channel::tls::server_config;
use futures_util::stream;
use rustls::version::{TLS12, TLS13};
use std::io;
use std::net::SocketAddr;
use tempfile::tempdir;
use tonic::transport::Endpoint;
use tonic::{Code, Request};


const CLOSED_PORT_ADDRESS: &str = "127.0.0.1:1";


const TWO_URIS: usize = 2;


const SECOND_URI: &str = "urn:ostyr:agent:acme:agent-2";


const FOREIGN_URI: &str = "https://example.com/agent";


#[tokio::test]
async fn mutual_handshake_and_heartbeat_succeed() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let server = start_server(&server_paths(dir.path(), &platform)?).await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let reply = bounded(attempt(server.address, &paths)).await??;
    assert_eq!(reply.tenant, "acme");
    assert_eq!(reply.agent_id, "agent-1");
    stop_server(server).await
}


#[tokio::test]
async fn certificate_with_a_dns_name_and_one_identity_uri_is_accepted() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let server = start_server(&server_paths(dir.path(), &platform)?).await?;
    let spec = LeafSpec {
        dns: vec!["agent.example".to_string()],
        ..agent_spec(&[AGENT_URI])
    };
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &spec)?;
    let reply = bounded(attempt(server.address, &paths)).await??;
    assert_eq!(reply.agent_id, "agent-1");
    stop_server(server).await
}


#[tokio::test]
async fn client_without_certificate_is_refused() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let server = start_single(&server_paths(dir.path(), &platform)?).await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let outcome = bounded(attempt_with(server.address, custom_client(&paths, &[&TLS13], false)?)).await?;
    assert!(outcome.is_err());
    let served = finish(server).await?;
    assert!(matches!(served, Err(ChannelError::Handshake(_))));
    Ok(())
}


#[tokio::test]
async fn certificate_from_another_authority_is_refused() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let intruder = make_authority()?;
    let server = start_single(&server_paths(dir.path(), &platform)?).await?;
    let paths = client_paths(dir.path(), "agent", &platform, &intruder, &agent_spec(&[AGENT_URI]))?;
    let outcome = bounded(attempt(server.address, &paths)).await?;
    assert!(outcome.is_err());
    let served = finish(server).await?;
    assert!(matches!(served, Err(ChannelError::Handshake(_))));
    Ok(())
}


#[tokio::test]
async fn expired_certificate_is_refused() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let server = start_single(&server_paths(dir.path(), &platform)?).await?;
    let spec = LeafSpec {
        expired: true,
        ..agent_spec(&[AGENT_URI])
    };
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &spec)?;
    let outcome = bounded(attempt(server.address, &paths)).await?;
    assert!(outcome.is_err());
    let served = finish(server).await?;
    assert!(matches!(served, Err(ChannelError::Handshake(_))));
    Ok(())
}


#[tokio::test]
async fn certificate_without_identity_uri_is_refused() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let server = start_single(&server_paths(dir.path(), &platform)?).await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[]))?;
    let outcome = bounded(attempt(server.address, &paths)).await?;
    assert!(outcome.is_err());
    let served = finish(server).await?;
    assert!(matches!(served, Err(ChannelError::Identity(IdentityError::UriCount(0)))));
    Ok(())
}


#[tokio::test]
async fn certificate_with_two_uris_is_refused() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let server = start_single(&server_paths(dir.path(), &platform)?).await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI, SECOND_URI]))?;
    let outcome = bounded(attempt(server.address, &paths)).await?;
    assert!(outcome.is_err());
    let served = finish(server).await?;
    assert!(matches!(served, Err(ChannelError::Identity(IdentityError::UriCount(TWO_URIS)))));
    Ok(())
}


#[tokio::test]
async fn certificate_with_a_foreign_uri_is_refused() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let server = start_single(&server_paths(dir.path(), &platform)?).await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[FOREIGN_URI]))?;
    let outcome = bounded(attempt(server.address, &paths)).await?;
    assert!(outcome.is_err());
    let served = finish(server).await?;
    assert!(matches!(served, Err(ChannelError::Identity(IdentityError::BadUri(_)))));
    Ok(())
}


#[tokio::test]
async fn tls_12_only_client_is_refused() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let server = start_single(&server_paths(dir.path(), &platform)?).await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let outcome = bounded(attempt_with(server.address, custom_client(&paths, &[&TLS12], true)?)).await?;
    assert!(outcome.is_err());
    let served = finish(server).await?;
    assert!(matches!(served, Err(ChannelError::Handshake(_))));
    Ok(())
}


#[tokio::test]
async fn server_certificate_for_another_name_is_refused() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let server = start_server(&server_paths(dir.path(), &platform)?).await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let config = custom_client(&paths, &[&TLS13], true)?;
    let outcome = bounded(async {
        let channel = connect_channel(server.address, config, "other.example").await?;
        heartbeat(channel, "test").await
    })
    .await?;
    assert!(outcome.is_err());
    stop_server(server).await
}


#[tokio::test]
async fn invalid_server_name_is_refused() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let address: SocketAddr = CLOSED_PORT_ADDRESS.parse()?;
    let outcome = connect_channel(address, custom_client(&paths, &[&TLS13], true)?, "not a name").await;
    assert!(matches!(outcome, Err(ChannelError::ServerName(_))));
    Ok(())
}


#[tokio::test]
async fn connection_to_a_closed_port_fails() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let address: SocketAddr = CLOSED_PORT_ADDRESS.parse()?;
    let outcome = bounded(attempt(address, &paths)).await?;
    assert!(matches!(outcome, Err(ChannelError::Transport(_))));
    Ok(())
}


#[tokio::test]
async fn heartbeat_on_a_dead_channel_reports_the_status() -> TestResult {
    let channel = Endpoint::from_static("http://127.0.0.1:1").connect_lazy();
    let outcome = bounded(heartbeat(channel, "test")).await?;
    assert!(matches!(outcome, Err(ChannelError::Status(_))));
    Ok(())
}


#[tokio::test]
async fn beat_without_verified_identity_is_unauthenticated() -> TestResult {
    let outcome = beat(Request::new(BeatRequest {
        agent_version: "test".to_string(),
    }))
    .await;
    assert_eq!(outcome.err().map(|status| status.code()), Some(Code::Unauthenticated));
    Ok(())
}


#[tokio::test]
async fn beat_answers_with_the_identity_in_the_request_extensions() -> TestResult {
    let mut request = Request::new(BeatRequest {
        agent_version: "test".to_string(),
    });
    request.extensions_mut().insert(Identity {
        tenant: "acme".to_string(),
        agent_id: "agent-9".to_string(),
    });
    let reply = beat(request).await?.into_inner();
    assert_eq!((reply.tenant.as_str(), reply.agent_id.as_str()), ("acme", "agent-9"));
    Ok(())
}


#[tokio::test]
async fn accept_errors_are_logged_and_serving_goes_on() -> TestResult {
    init_logging()?;
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let config = server_config(&paths)?;
    let incoming = stream::iter(vec![Err(io::Error::other("accept failed"))]);
    let revocation = empty_revocation(&paths)?;
    bounded(serve(
        Box::pin(incoming),
        config,
        channel_router(),
        revocation.watcher,
        Box::pin(std::future::pending()),
    ))
    .await?;
    Ok(())
}


#[test]
fn connection_outcomes_are_logged() -> TestResult {
    init_logging()?;
    log_outcome(Ok(()));
    log_outcome(Err(ChannelError::NoCertificate { path: "x".into() }));
    Ok(())
}


#[tokio::test]
async fn connection_ends_cleanly_when_the_agent_disconnects() -> TestResult {
    let dir = tempdir()?;
    let platform = make_platform()?;
    let server = start_single(&server_paths(dir.path(), &platform)?).await?;
    let paths = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let reply = bounded(attempt(server.address, &paths)).await??;
    let served = finish(server).await?;
    assert_eq!(reply.agent_id, "agent-1");
    assert!(served.is_ok());
    Ok(())
}
