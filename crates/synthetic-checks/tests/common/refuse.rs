use socket2::{Domain, Socket, Type};
use std::io;
use std::net::{Ipv4Addr, SocketAddr};


pub struct Refusing {
    pub address: SocketAddr,
    _socket: Socket,
}


pub fn refusing() -> io::Result<Refusing> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, None)?;
    socket.bind(&SocketAddr::new(Ipv4Addr::LOCALHOST.into(), 0).into())?;
    let address = socket
        .local_addr()?
        .as_socket()
        .ok_or_else(|| io::Error::other("not an internet address"))?;
    Ok(Refusing { address, _socket: socket })
}
