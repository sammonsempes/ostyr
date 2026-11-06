use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_stream::Stream;


pub type SharedServerConfig = Arc<rustls::ServerConfig>;


pub type SharedClientConfig = Arc<rustls::ClientConfig>;


pub type IncomingConnections = Pin<Box<dyn Stream<Item = io::Result<TcpStream>> + Send>>;


pub type ShutdownSignal = Pin<Box<dyn Future<Output = ()> + Send>>;
