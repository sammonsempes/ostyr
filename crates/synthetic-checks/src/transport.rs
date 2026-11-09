use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;


/// The real `Connect`: a TCP connect to the checked socket within the time left; the stream is closed on return.
pub fn tcp_connect(socket: SocketAddr, left: Duration) -> io::Result<()> {
    TcpStream::connect_timeout(&socket, left).map(drop)
}
