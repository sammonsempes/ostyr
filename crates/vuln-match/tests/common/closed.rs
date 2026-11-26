use socket2::{Domain, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};


/// A bound, never listening socket: a connection to its port is refused for as long as the socket lives.
pub fn closed_socket() -> io::Result<(Socket, u16)> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.bind(&SocketAddr::from((Ipv4Addr::LOCALHOST, 0)).into())?;
    let port = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("not an inet address"))?
        .port();
    Ok((socket, port))
}
