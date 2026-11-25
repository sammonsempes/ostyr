use crate::model::Check;
use crate::probe::{FetchCaps, HttpRequest, HttpResponse};
use alerts::error::StoreError;
use alerts::model::Alert;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;


pub type Clock<'a> = dyn Fn() -> Duration + 'a;


/// Takes the name, the time left and the answer cap.
pub type Resolve<'a> = dyn Fn(&str, Duration, usize) -> io::Result<Vec<IpAddr>> + 'a;


/// Takes the request, the time left and the caps on what it may buffer.
pub type Fetch<'a> = dyn Fn(&HttpRequest, Duration, FetchCaps) -> io::Result<HttpResponse> + 'a;


pub type Connect<'a> = dyn Fn(SocketAddr, Duration) -> io::Result<()> + 'a;


/// Takes the socket, the server name, the time left, the certificate count cap and the per-certificate byte cap.
pub type Handshake<'a> = dyn Fn(SocketAddr, &str, Duration, usize, usize) -> io::Result<Vec<Vec<u8>>> + 'a;


/// One echo request to the address, `Ok` when the matching reply arrives within the time left.
pub type Ping<'a> = dyn Fn(IpAddr, Duration) -> io::Result<()> + 'a;


/// Probes one check and answers whether it succeeded.
pub type Probe<'a> = dyn Fn(&Check) -> bool + 'a;


/// Wall-clock seconds since the epoch.
pub type WallClock<'a> = dyn Fn() -> u64 + 'a;


/// Stores the alerts and answers how many were new.
pub type Store<'a> = dyn Fn(&[Alert]) -> Result<usize, StoreError> + 'a;


pub type Stopped<'a> = dyn Fn() -> bool + 'a;


/// Sleeps for one slice of the pause between rounds.
pub type Sleep<'a> = dyn Fn(Duration) + 'a;


/// The real `Fetch` with the CA roots of the loaded checks file as its last argument.
pub type RootedFetch<'a> = dyn Fn(&HttpRequest, Duration, FetchCaps, &[Vec<u8>]) -> io::Result<HttpResponse> + 'a;


/// The one read of the service file at start.
pub type StartRead = fn(&std::path::Path) -> Result<crate::serve::ServiceSettings, core_config::error::ConfigError>;


/// Where the stop flag comes from: the signals in production.
pub type StopSource = fn() -> io::Result<std::sync::Arc<std::sync::atomic::AtomicBool>>;
