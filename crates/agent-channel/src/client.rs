use crate::error::ChannelError;
use crate::model::{CONNECT_TIMEOUT_SECONDS, HEARTBEAT_PATH, PLACEHOLDER_ENDPOINT};
use crate::proto::{BeatReply, BeatRequest};
use crate::types::SharedClientConfig;
use http::uri::PathAndQuery;
use http::Uri;
use hyper_util::rt::TokioIo;
use rustls_pki_types::ServerName;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tonic::client::Grpc;
use tonic::transport::{Channel, Endpoint};
use tonic_prost::ProstCodec;
use tower::service_fn;


/// Connects over TLS 1.3, verifying the server certificate against the configured CA and `server_name`.
pub async fn connect_channel(address: SocketAddr, config: SharedClientConfig, server_name: &str) -> Result<Channel, ChannelError> {
    let name = ServerName::try_from(server_name.to_string())?;
    let connector = TlsConnector::from(config);
    let service = service_fn(move |_uri: Uri| {
        let attempt_connector = connector.clone();
        let attempt_name = name.clone();
        async move {
            let tcp = TcpStream::connect(address).await?;
            let tls = attempt_connector.connect(attempt_name, tcp).await?;
            Ok::<_, io::Error>(TokioIo::new(tls))
        }
    });
    let channel = Endpoint::from_static(PLACEHOLDER_ENDPOINT)
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECONDS))
        .connect_with_connector(service)
        .await?;
    Ok(channel)
}


pub async fn heartbeat(channel: Channel, agent_version: &str) -> Result<BeatReply, ChannelError> {
    let mut grpc = Grpc::new(channel);
    grpc.ready().await?;
    let reply = grpc
        .unary(
            tonic::Request::new(BeatRequest {
                agent_version: agent_version.to_string(),
            }),
            PathAndQuery::from_static(HEARTBEAT_PATH),
            ProstCodec::<BeatRequest, BeatReply>::default(),
        )
        .await
        .map_err(|status| ChannelError::Status(Box::new(status)))?;
    Ok(reply.into_inner())
}
