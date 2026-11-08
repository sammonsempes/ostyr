use crate::harness::{
    attempt, bounded, client_paths, empty_revocation, make_platform, scoped_logging, server_paths, start_server_state, stop_server,
};
use crate::pki::{agent_spec, AGENT_URI, SERVER_NAME};
use crate::services::{agent_identity, recording_state, settings};
use crate::types::TestResult;
use agent_channel::client::{connect_channel, heartbeat};
use agent_channel::limits::lock_load;
use agent_channel::model::{SERVER_KEEPALIVE_INTERVAL_SECONDS, SERVER_KEEPALIVE_TIMEOUT_SECONDS};
use agent_channel::tls::client_config;
use agent_channel::types::SharedState;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tempfile::tempdir;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
use tokio::time::sleep;


const AGENT_CONNECTIONS: usize = 4;


const SLACK_SECONDS: u64 = 5;


const POLL_ATTEMPTS: u32 = 100;


const POLL_MILLIS: u64 = 10;


async fn relay(mut agent: TcpStream, mut server: TcpStream, blackhole: Arc<Notify>) {
    tokio::select! {
        copied = copy_bidirectional(&mut agent, &mut server) => {
            tracing::debug!(?copied, "relay ended");
        }
        () = blackhole.notified() => std::future::pending::<()>().await,
    }
}


async fn start_proxy(target: SocketAddr, blackhole: Arc<Notify>) -> Result<(SocketAddr, JoinHandle<()>), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let handle = tokio::spawn(async move {
        let mut relays = Vec::new();
        while relays.len() < AGENT_CONNECTIONS {
            match listener.accept().await {
                Ok((agent, _peer)) => match TcpStream::connect(target).await {
                    Ok(server) => relays.push(tokio::spawn(relay(agent, server, Arc::clone(&blackhole)))),
                    Err(error) => tracing::warn!(%error, "proxy cannot reach the server"),
                },
                Err(error) => tracing::warn!(%error, "proxy accept failed"),
            }
        }
        relays
            .iter()
            .for_each(|held| tracing::debug!(finished = held.is_finished(), "relay kept"));
        std::future::pending::<()>().await;
    });
    Ok((address, handle))
}


fn connections(state: &SharedState) -> usize {
    lock_load(state).get(&agent_identity()).map_or(0, |load| load.connections)
}


async fn wait_for_connections(state: &SharedState, expected: usize) -> TestResult {
    let mut attempts = 0;
    while connections(state) != expected && attempts < POLL_ATTEMPTS {
        sleep(Duration::from_millis(POLL_MILLIS)).await;
        attempts += 1;
    }
    assert_eq!(connections(state), expected);
    Ok(())
}


#[tokio::test]
async fn blackholed_agent_connections_are_dropped_by_the_server_keepalive() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(settings(|base| base.max_connections_per_agent = AGENT_CONNECTIONS));
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let server = start_server_state(&paths, empty_revocation(&paths)?, Arc::clone(&state)).await?;
    let agent = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let blackhole = Arc::new(Notify::new());
    let (proxy_address, proxy) = start_proxy(server.address, Arc::clone(&blackhole)).await?;
    let mut channels = Vec::new();
    for _agent_connection in 0..AGENT_CONNECTIONS {
        let channel = bounded(connect_channel(proxy_address, client_config(&agent)?, SERVER_NAME)).await??;
        bounded(heartbeat(channel.clone(), "test")).await??;
        channels.push(channel);
    }
    wait_for_connections(&state, AGENT_CONNECTIONS).await?;
    assert!(bounded(attempt(server.address, &agent)).await?.is_err());
    blackhole.notify_waiters();
    tokio::time::pause();
    sleep(Duration::from_secs(
        SERVER_KEEPALIVE_INTERVAL_SECONDS + SERVER_KEEPALIVE_TIMEOUT_SECONDS + SLACK_SECONDS,
    ))
    .await;
    wait_for_connections(&state, 0).await?;
    tokio::time::resume();
    assert!(bounded(attempt(server.address, &agent)).await?.is_ok());
    assert_eq!(channels.len(), AGENT_CONNECTIONS);
    proxy.abort();
    stop_server(server).await
}
