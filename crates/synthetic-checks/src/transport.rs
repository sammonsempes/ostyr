use crate::error::PingSocketError;
use socket2::{Domain, Protocol, Socket, Type};
use std::io;
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};


pub const ECHO_PAYLOAD_BYTES: usize = 16;


pub const MAX_FOREIGN_REPLIES: usize = 8;


pub const ICMP_HEADER_BYTES: usize = 8;


pub const RECEIVE_BUFFER_BYTES: usize = 128;


pub const ECHO_REQUEST_V4: u8 = 8;


pub const ECHO_REPLY_V4: u8 = 0;


pub const ECHO_REQUEST_V6: u8 = 128;


pub const ECHO_REPLY_V6: u8 = 129;


pub const FOREIGN_FLOOD: &str = "too many foreign ICMP packets before the reply";


/// The real `Connect`: a TCP connect to the checked socket within the time left; the stream is closed on return.
pub fn tcp_connect(socket: SocketAddr, left: Duration) -> io::Result<()> {
    TcpStream::connect_timeout(&socket, left).map(drop)
}


/// The echo request message: type, code 0, checksum and identifier left to the kernel, sequence 1, then the payload.
pub fn echo_request(target: IpAddr, payload: &[u8]) -> Vec<u8> {
    let request_type = if target.is_ipv4() { ECHO_REQUEST_V4 } else { ECHO_REQUEST_V6 };
    [request_type, 0, 0, 0, 0, 0, 0, 1].into_iter().chain(payload.iter().copied()).collect()
}


/// A reply counts only if it is an echo reply of the probed family, carries exactly our payload and comes from the probed address.
pub fn reply_matches(reply: &[u8], source: IpAddr, target: IpAddr, payload: &[u8]) -> bool {
    let reply_type = if target.is_ipv4() { ECHO_REPLY_V4 } else { ECHO_REPLY_V6 };
    let genuine = reply
        .split_at_checked(ICMP_HEADER_BYTES)
        .is_some_and(|(header, body)| header.first() == Some(&reply_type) && body == payload);
    genuine && source.to_canonical() == target.to_canonical()
}


/// Reads packets until one matches; a packet that does not match is dropped, at most `MAX_FOREIGN_REPLIES` of them.
pub fn await_reply(next: &mut dyn FnMut() -> io::Result<(Vec<u8>, IpAddr)>, target: IpAddr, payload: &[u8]) -> io::Result<()> {
    (0..MAX_FOREIGN_REPLIES)
        .find_map(|_| match next() {
            Ok((reply, source)) => reply_matches(&reply, source, target, payload).then_some(Ok(())),
            Err(error) => Some(Err(error)),
        })
        .unwrap_or_else(|| Err(io::Error::new(io::ErrorKind::TimedOut, FOREIGN_FLOOD)))
}


/// A read timeout surfaces as `WouldBlock`; it is a `TimedOut` for the probe.
pub fn timeout_kind(error: io::Error) -> io::Error {
    match error.kind() {
        io::ErrorKind::WouldBlock => io::Error::from(io::ErrorKind::TimedOut),
        _ => error,
    }
}


/// The socket could not be created: the fixed error says to check `ping_group_range`, the cause is kept.
pub fn refused_socket(error: io::Error) -> io::Error {
    io::Error::new(error.kind(), PingSocketError(error))
}


/// One read of at most `RECEIVE_BUFFER_BYTES` before `deadline`: the packet and its source address.
pub fn receive(socket: &UdpSocket, deadline: Instant) -> io::Result<(Vec<u8>, IpAddr)> {
    let left = deadline
        .checked_duration_since(Instant::now())
        .filter(|left| !left.is_zero())
        .ok_or_else(|| io::Error::from(io::ErrorKind::TimedOut))?;
    socket.set_read_timeout(Some(left))?;
    let mut buffer: [u8; RECEIVE_BUFFER_BYTES] = [0; RECEIVE_BUFFER_BYTES];
    let (length, from) = socket.recv_from(&mut buffer).map_err(timeout_kind)?;
    Ok((buffer.iter().take(length).copied().collect(), from.ip()))
}


/// An unprivileged ICMP datagram socket connected to the target: the kernel owns the identifier and only delivers replies to our requests.
pub fn open_ping_socket(target: IpAddr) -> io::Result<UdpSocket> {
    let (domain, protocol) = if target.is_ipv4() {
        (Domain::IPV4, Protocol::ICMPV4)
    } else {
        (Domain::IPV6, Protocol::ICMPV6)
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(protocol)).map_err(refused_socket)?;
    socket.connect(&SocketAddr::new(target, 0).into())?;
    Ok(socket.into())
}


/// The real `Ping` on unix: one echo request with a random payload, then the matching reply within `left`.
#[cfg(unix)]
pub fn icmp_echo(target: IpAddr, left: Duration) -> io::Result<()> {
    let deadline = Instant::now()
        .checked_add(left)
        .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    let socket = open_ping_socket(target)?;
    let mut payload: [u8; ECHO_PAYLOAD_BYTES] = [0; ECHO_PAYLOAD_BYTES];
    getrandom::fill(&mut payload).map_err(io::Error::other)?;
    socket.send(&echo_request(target, &payload))?;
    await_reply(&mut || receive(&socket, deadline), target, &payload)
}


#[cfg(not(unix))]
pub fn icmp_echo(_target: IpAddr, _left: Duration) -> io::Result<()> {
    Err(io::Error::from(io::ErrorKind::Unsupported))
}
