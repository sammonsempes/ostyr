use crate::model::{Accepted, Halves};
use futures_util::future::Shared;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use tokio::io::{AsyncRead, AsyncWrite};


pub type BoxRead = Box<dyn AsyncRead + Send + Unpin>;


pub type BoxWrite = Box<dyn AsyncWrite + Send + Unpin>;


pub type AcceptFuture = Pin<Box<dyn Future<Output = io::Result<Accepted>> + Send>>;


pub type AcceptFn = Box<dyn Fn() -> AcceptFuture + Send + Sync>;


pub type ConnectFuture = Pin<Box<dyn Future<Output = io::Result<Halves>> + Send>>;


pub type ConnectFn = Box<dyn Fn(SocketAddr) -> ConnectFuture + Send + Sync>;


pub type ShutdownSignal = Pin<Box<dyn Future<Output = ()> + Send>>;


pub type SharedStop = Shared<ShutdownSignal>;
