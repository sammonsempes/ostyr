use crate::probe::{HttpRequest, HttpResponse};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;


pub type Clock<'a> = dyn Fn() -> Duration + 'a;


pub type Resolve<'a> = dyn Fn(&str) -> io::Result<Vec<IpAddr>> + 'a;


pub type Fetch<'a> = dyn Fn(&HttpRequest, Duration, usize) -> io::Result<HttpResponse> + 'a;


pub type Connect<'a> = dyn Fn(SocketAddr, Duration) -> io::Result<()> + 'a;


pub type Handshake<'a> = dyn Fn(SocketAddr, &str, Duration) -> io::Result<Vec<Vec<u8>>> + 'a;
