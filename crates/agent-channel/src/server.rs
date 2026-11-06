use crate::error::{ChannelError, IdentityError};
use crate::identity::identity_from_chain;
use crate::model::{Identity, HEARTBEAT_PATH};
use crate::proto::{BeatReply, BeatRequest};
use crate::types::{IncomingConnections, SharedServerConfig, ShutdownSignal};
use axum::body::Body;
use axum::{Extension, Router};
use futures_util::{FutureExt, StreamExt};
use http::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use std::convert::Infallible;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tonic::server::Grpc;
use tonic_prost::ProstCodec;
use tower::service_fn;


pub fn channel_router() -> Router {
    Router::new().route_service(HEARTBEAT_PATH, service_fn(heartbeat_route))
}


pub async fn heartbeat_route(request: Request<Body>) -> Result<Response<tonic::body::Body>, Infallible> {
    Ok(Grpc::new(ProstCodec::<BeatReply, BeatRequest>::default())
        .unary(service_fn(beat), request)
        .await)
}


/// Answers with the identity taken from the certificate; the request names no agent and no tenant.
pub async fn beat(request: tonic::Request<BeatRequest>) -> Result<tonic::Response<BeatReply>, tonic::Status> {
    let identity = request
        .extensions()
        .get::<Identity>()
        .ok_or_else(|| tonic::Status::unauthenticated("no verified agent identity"))?;
    Ok(tonic::Response::new(BeatReply {
        tenant: identity.tenant.clone(),
        agent_id: identity.agent_id.clone(),
    }))
}


/// Accepts connections until `shutdown` completes; every connection runs in its own task and a refused one is logged.
pub async fn serve(incoming: IncomingConnections, config: SharedServerConfig, router: Router, shutdown: ShutdownSignal) {
    let acceptor = TlsAcceptor::from(config);
    incoming
        .take_until(shutdown)
        .for_each(|accepted| {
            match accepted {
                Ok(stream) => {
                    let connection = run_connection(stream, acceptor.clone(), router.clone());
                    tokio::spawn(connection.map(log_outcome));
                }
                Err(error) => tracing::warn!(%error, "accept failed"),
            }
            std::future::ready(())
        })
        .await;
}


/// Handshake (client certificate verified by rustls), identity from the certificate, then HTTP/2 with the identity attached to every request.
pub async fn run_connection(stream: TcpStream, acceptor: TlsAcceptor, router: Router) -> Result<(), ChannelError> {
    let tls = acceptor.accept(stream).await.map_err(ChannelError::Handshake)?;
    let identity = identity_from_chain(tls.get_ref().1.peer_certificates()).map_err(refuse)?;
    let service = router.layer(Extension(identity));
    Builder::new(TokioExecutor::new())
        .http2_only()
        .serve_connection(TokioIo::new(tls), TowerToHyperService::new(service))
        .await
        .map_err(ChannelError::Serve)
}


pub fn refuse(error: IdentityError) -> ChannelError {
    tracing::warn!(%error, "client certificate refused");
    ChannelError::Identity(error)
}


pub fn log_outcome(outcome: Result<(), ChannelError>) {
    if let Err(error) = outcome {
        tracing::warn!(%error, "agent connection ended");
    }
}
