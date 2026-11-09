use crate::probe::{FetchCaps, HttpRequest, HttpResponse};
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
