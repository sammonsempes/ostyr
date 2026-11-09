use crate::harness::{
    attempt, bounded, client_paths, empty_revocation, make_platform, scoped_logging, server_paths, start_server_state, start_single_state,
    stop_server,
};
use crate::pki::{agent_spec, AGENT_URI, SERVER_NAME};
use crate::services::{agent_identity, counter, recording_state, settings};
use crate::types::TestResult;
use agent_channel::error::ChannelError;
use agent_channel::limits::lock_load;
use agent_channel::model::ClientTlsPaths;
use agent_channel::server::{keepalive_settings, log_keepalive, set_keepalive};
use agent_channel::settings::validate_settings;
use agent_channel::tls::client_config;
use agent_channel::types::SharedState;
use rustls_pki_types::ServerName;
use std::io;
use std::net::SocketAddr;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;


const HTTP2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";


const EMPTY_SETTINGS_FRAME: [u8; 9] = [0, 0, 0, 4, 0, 0, 0, 0, 0];


async fn silent_client(address: SocketAddr, paths: &ClientTlsPaths) -> Result<TlsStream<TcpStream>, Box<dyn std::error::Error>> {
    let connector = TlsConnector::from(client_config(paths)?);
    let tcp = TcpStream::connect(address).await?;
    Ok(connector.connect(ServerName::try_from(SERVER_NAME)?, tcp).await?)
}


fn agent_connections(state: &SharedState) -> usize {
    lock_load(state).get(&agent_identity()).map_or(0, |load| load.connections)
}


#[tokio::test]
async fn a_client_sending_nothing_after_tls_is_dropped_at_the_deadline() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(settings(|_base| ()));
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let server = start_single_state(&paths, empty_revocation(&paths)?, state.clone()).await?;
    let agent = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let _silent = silent_client(server.address, &agent).await?;
    tokio::time::pause();
    let served = server.handle.await?;
    assert!(matches!(served, Err(ChannelError::FirstRequestTimeout { .. })));
    assert_eq!(counter(&state.counters.first_request_timeouts), 1);
    Ok(())
}


#[tokio::test]
async fn permits_are_released_and_the_agent_reconnects_after_a_silent_connection() -> TestResult {
    let _logging = scoped_logging();
    let (state, _stored) = recording_state(settings(|base| base.max_connections_per_agent = 1));
    let dir = tempdir()?;
    let platform = make_platform()?;
    let paths = server_paths(dir.path(), &platform)?;
    let server = start_server_state(&paths, empty_revocation(&paths)?, state.clone()).await?;
    let agent = client_paths(dir.path(), "agent", &platform, &platform.agent_ca, &agent_spec(&[AGENT_URI]))?;
    let mut silent = silent_client(server.address, &agent).await?;
    silent.write_all(HTTP2_PREFACE).await?;
    silent.write_all(&EMPTY_SETTINGS_FRAME).await?;
    silent.flush().await?;
    tokio::time::pause();
    let mut sink = Vec::new();
    let read = silent.read_to_end(&mut sink).await;
    tokio::time::resume();
    tracing::debug!(?read, "silent connection closed by the server");
    assert_eq!(counter(&state.counters.first_request_timeouts), 1);
    assert_eq!(agent_connections(&state), 0);
    assert!(bounded(attempt(server.address, &agent)).await?.is_ok());
    stop_server(server).await
}


#[tokio::test]
async fn keepalive_is_set_on_a_real_socket_and_failures_are_logged() -> TestResult {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let client = TcpStream::connect(listener.local_addr()?).await?;
    set_keepalive(&client)?;
    log_keepalive(Ok(()));
    log_keepalive(Err(io::Error::other("refused")));
    assert!(format!("{:?}", keepalive_settings()).contains("TcpKeepalive"));
    Ok(())
}


#[test]
fn a_zero_first_request_deadline_is_refused() -> TestResult {
    let bad = settings(|base| base.first_request_timeout_seconds = 0);
    let message = validate_settings(&bad).err().ok_or("accepted")?.to_string();
    assert!(message.contains("first_request_timeout_seconds"));
    Ok(())
}
