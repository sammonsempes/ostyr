use crate::error::{ChannelError, IdentityError};
use crate::identity::{identity_from_chain, serial_from_chain};
use crate::revocation::{is_revoked, is_revoked_now};
use crate::types::{IncomingConnections, RevocationWatch, SharedServerConfig, ShutdownSignal};
use axum::{Extension, Router};
use futures_util::{FutureExt, StreamExt};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;


/// Accepts connections until `shutdown` completes; every connection runs in its own task and a refused one is logged.
pub async fn serve(
    incoming: IncomingConnections,
    config: SharedServerConfig,
    router: Router,
    revocations: RevocationWatch,
    shutdown: ShutdownSignal,
) {
    let acceptor = TlsAcceptor::from(config);
    incoming
        .take_until(shutdown)
        .for_each(|accepted| {
            match accepted {
                Ok(stream) => {
                    let connection = run_connection(stream, acceptor.clone(), router.clone(), revocations.clone());
                    tokio::spawn(connection.map(log_outcome));
                }
                Err(error) => tracing::warn!(%error, "accept failed"),
            }
            std::future::ready(())
        })
        .await;
}


/// Handshake, identity and serial from the certificate, then HTTP/2; the connection ends as soon as the serial is revoked.
pub async fn run_connection(stream: TcpStream, acceptor: TlsAcceptor, router: Router, revocations: RevocationWatch) -> Result<(), ChannelError> {
    let tls = acceptor.accept(stream).await.map_err(ChannelError::Handshake)?;
    let identity = identity_from_chain(tls.get_ref().1.peer_certificates()).map_err(refuse)?;
    let serial = serial_from_chain(tls.get_ref().1.peer_certificates()).map_err(refuse)?;
    if is_revoked_now(&revocations, &serial) {
        Err(refused_revoked(serial))
    } else {
        let service = router.layer(Extension(identity));
        let builder = Builder::new(TokioExecutor::new()).http2_only();
        tokio::select! {
            served = builder.serve_connection(TokioIo::new(tls), TowerToHyperService::new(service)) => {
                served.map_err(ChannelError::Serve)
            }
            closed = watch_revocation(revocations, &serial) => Err(closed),
        }
    }
}


pub fn refused_revoked(serial: String) -> ChannelError {
    tracing::warn!(%serial, "revoked agent certificate refused");
    ChannelError::Revoked { serial }
}


/// Completes with the reason as soon as `serial` is on the list, or when the list is no longer maintained.
pub async fn watch_revocation(mut revocations: RevocationWatch, serial: &str) -> ChannelError {
    let outcome = revocations.wait_for(|list| is_revoked(list, serial)).await.map(|_list| ());
    match outcome {
        Ok(()) => refused_revoked(serial.to_owned()),
        Err(source) => ChannelError::RevocationClosed(source),
    }
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
