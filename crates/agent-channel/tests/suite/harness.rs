use crate::pki::{issue, make_authority, server_spec, write_file, write_leaf, Authority, LeafSpec, SERVER_NAME, WORLD_READABLE_MODE};
use crate::revocation_support::{open_revocation, Revocation, RevocationControl};
use crate::state::default_state;
use agent_channel::client::{connect_channel, heartbeat};
use agent_channel::error::ChannelError;
use agent_channel::model::{Admission, ClientTlsPaths, ServerTlsPaths, ALPN_H2};
use agent_channel::proto::BeatReply;
use agent_channel::server::{run_connection, serve};
use agent_channel::services::channel_router;
use agent_channel::tls::{client_config, parse_private_key, provider, read_certificates, read_private_key, root_store, server_config};
use agent_channel::types::{SharedClientConfig, SharedState};
use rustls::{ClientConfig, SupportedProtocolVersion};
use std::error::Error;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Semaphore};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use tokio_rustls::TlsAcceptor;
use tokio_stream::wrappers::TcpListenerStream;


static LOGGING: LazyLock<Option<String>> = LazyLock::new(|| {
    tracing_subscriber::fmt()
        .with_writer(std::io::sink)
        .try_init()
        .err()
        .map(|error| error.to_string())
});


pub fn scoped_logging() -> tracing::subscriber::DefaultGuard {
    tracing::subscriber::set_default(tracing_subscriber::fmt().with_writer(std::io::sink).finish())
}


pub fn init_logging() -> Result<(), Box<dyn Error>> {
    LOGGING.as_deref().map_or(Ok(()), |message| Err(message.into()))
}


pub const CALL_TIMEOUT_SECONDS: u64 = 10;


pub struct Platform {
    pub agent_ca: Authority,
    pub platform_ca: Authority,
}


pub struct RunningServer {
    pub address: SocketAddr,
    pub shutdown: oneshot::Sender<()>,
    pub handle: JoinHandle<()>,
    pub control: RevocationControl,
}


pub fn make_platform() -> Result<Platform, Box<dyn Error>> {
    Ok(Platform {
        agent_ca: make_authority()?,
        platform_ca: make_authority()?,
    })
}


pub fn server_paths(dir: &Path, platform: &Platform) -> Result<ServerTlsPaths, Box<dyn Error>> {
    let files = write_leaf(dir, "server", &issue(&platform.platform_ca, &server_spec())?)?;
    Ok(ServerTlsPaths {
        certificate: files.certificate,
        key: files.key,
        agent_ca: write_file(dir, "agent-ca.pem", &platform.agent_ca.pem, WORLD_READABLE_MODE)?,
    })
}


pub fn client_paths(dir: &Path, name: &str, platform: &Platform, agent: &Authority, spec: &LeafSpec) -> Result<ClientTlsPaths, Box<dyn Error>> {
    let files = write_leaf(dir, name, &issue(agent, spec)?)?;
    Ok(ClientTlsPaths {
        certificate: files.certificate,
        key: files.key,
        platform_ca: write_file(dir, "platform-ca.pem", &platform.platform_ca.pem, WORLD_READABLE_MODE)?,
    })
}


pub fn empty_revocation(paths: &ServerTlsPaths) -> Result<Revocation, Box<dyn Error>> {
    let dir = paths.certificate.parent().ok_or("certificate has no directory")?;
    open_revocation(dir, &[])
}


pub async fn start_server(paths: &ServerTlsPaths) -> Result<RunningServer, Box<dyn Error>> {
    start_server_with(paths, empty_revocation(paths)?).await
}


pub async fn start_server_with(paths: &ServerTlsPaths, revocation: Revocation) -> Result<RunningServer, Box<dyn Error>> {
    start_server_state(paths, revocation, default_state()).await
}


pub async fn start_server_state(paths: &ServerTlsPaths, revocation: Revocation, state: SharedState) -> Result<RunningServer, Box<dyn Error>> {
    start_server_at(paths, revocation, state, "127.0.0.1:0").await
}


pub async fn start_server_at(
    paths: &ServerTlsPaths,
    revocation: Revocation,
    state: SharedState,
    bind: &str,
) -> Result<RunningServer, Box<dyn Error>> {
    init_logging()?;
    let listener = TcpListener::bind(bind).await?;
    let address = listener.local_addr()?;
    let (shutdown, receiver) = oneshot::channel::<()>();
    let config = server_config(paths)?;
    let handle = tokio::spawn(serve(
        Box::pin(TcpListenerStream::new(listener)),
        config,
        channel_router(Arc::clone(&state)),
        state,
        revocation.watcher,
        Box::pin(async move {
            if let Err(error) = receiver.await {
                tracing::warn!(%error, "shutdown sender dropped");
            }
        }),
    ));
    Ok(RunningServer {
        address,
        shutdown,
        handle,
        control: revocation.control,
    })
}


pub struct SingleServer {
    pub address: SocketAddr,
    pub handle: JoinHandle<Result<(), ChannelError>>,
    pub control: RevocationControl,
}


pub async fn start_single(paths: &ServerTlsPaths) -> Result<SingleServer, Box<dyn Error>> {
    start_single_with(paths, empty_revocation(paths)?).await
}


pub async fn start_single_with(paths: &ServerTlsPaths, revocation: Revocation) -> Result<SingleServer, Box<dyn Error>> {
    start_single_state(paths, revocation, default_state()).await
}


pub fn single_admission(state: &SharedState) -> Admission {
    let (_never_evicted, evicted) = oneshot::channel();
    Admission {
        connections: Arc::new(Semaphore::new(state.settings.max_total_connections)),
        evicted,
    }
}


pub async fn start_single_state(paths: &ServerTlsPaths, revocation: Revocation, state: SharedState) -> Result<SingleServer, Box<dyn Error>> {
    init_logging()?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let address = listener.local_addr()?;
    let acceptor = TlsAcceptor::from(server_config(paths)?);
    let handle = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.map_err(ChannelError::Handshake)?;
        let admission = single_admission(&state);
        run_connection(stream, acceptor, channel_router(Arc::clone(&state)), state, revocation.watcher, admission).await
    });
    Ok(SingleServer {
        address,
        handle,
        control: revocation.control,
    })
}


pub async fn finish(server: SingleServer) -> Result<Result<(), ChannelError>, Box<dyn Error>> {
    Ok(bounded(server.handle).await??)
}


pub async fn stop_server(server: RunningServer) -> Result<(), Box<dyn Error>> {
    server.shutdown.send(()).map_err(|()| "server already stopped")?;
    server.handle.await?;
    Ok(())
}


pub async fn attempt(address: SocketAddr, paths: &ClientTlsPaths) -> Result<BeatReply, ChannelError> {
    let config = client_config(paths)?;
    let channel = connect_channel(address, config, SERVER_NAME).await?;
    heartbeat(channel, "test").await
}


pub async fn bounded<Output>(future: impl std::future::Future<Output = Output>) -> Result<Output, Box<dyn Error>> {
    Ok(timeout(Duration::from_secs(CALL_TIMEOUT_SECONDS), future).await?)
}


pub fn custom_client(
    paths: &ClientTlsPaths,
    versions: &[&'static SupportedProtocolVersion],
    present_certificate: bool,
) -> Result<SharedClientConfig, Box<dyn Error>> {
    let builder = ClientConfig::builder_with_provider(provider())
        .with_protocol_versions(versions)?
        .with_root_certificates(root_store(&paths.platform_ca)?);
    let mut config = if present_certificate {
        builder.with_client_auth_cert(
            read_certificates(&paths.certificate)?,
            parse_private_key(&read_private_key(&paths.key)?, &paths.key)?,
        )?
    } else {
        builder.with_no_client_auth()
    };
    config.alpn_protocols.push(ALPN_H2.to_vec());
    Ok(Arc::new(config))
}


pub async fn attempt_with(address: SocketAddr, config: SharedClientConfig) -> Result<BeatReply, ChannelError> {
    let channel = connect_channel(address, config, SERVER_NAME).await?;
    heartbeat(channel, "test").await
}
