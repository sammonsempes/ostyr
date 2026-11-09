use crate::model::{PageSettings, PageState};
use arc_swap::ArcSwap;
use std::error::Error;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_stream::Stream;


pub type SharedSettings = Arc<ArcSwap<PageSettings>>;


pub type SharedState = Arc<PageState>;


pub type BoxError = Box<dyn Error + Send + Sync>;


/// Reads the limiter clock in milliseconds; production passes `system_millis`.
pub type NowFn = dyn Fn() -> u64 + Send + Sync;


pub type IncomingConnections = Pin<Box<dyn Stream<Item = io::Result<TcpStream>> + Send>>;


pub type ShutdownSignal = Pin<Box<dyn Future<Output = ()> + Send>>;
