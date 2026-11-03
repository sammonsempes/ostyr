use crate::ecs::{to_json, EcsEvent};
use crate::error::ExportError;
use std::io::{self, Write};
use std::net::{SocketAddr, ToSocketAddrs, UdpSocket};
use time::format_description::well_known::Rfc3339;


pub const FACILITY_LOCAL0: u32 = 16;


pub const SEVERITY_INFORMATIONAL: u32 = 6;


pub const FACILITY_MULTIPLIER: u32 = 8;


pub const MAX_HOSTNAME_LEN: usize = 255;


pub const MAX_APP_NAME_LEN: usize = 48;


pub const MESSAGE_ID: &str = "ecs";


pub const NIL_VALUE: &str = "-";


pub const UDP_BIND_V4: &str = "0.0.0.0:0";


pub const UDP_BIND_V6: &str = "[::]:0";


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyslogHeader {
    pub hostname: String,
    pub app_name: String,
}


/// Keeps printable ASCII without space (RFC 5424 PRINTUSASCII), at most `max_len` characters; empty becomes the nil value.
pub fn header_token(raw: &str, max_len: usize) -> String {
    let cleaned: String = raw
        .chars()
        .take(max_len)
        .map(|character| if character.is_ascii_graphic() { character } else { '_' })
        .collect();
    if cleaned.is_empty() {
        NIL_VALUE.to_string()
    } else {
        cleaned
    }
}


pub fn priority() -> u32 {
    FACILITY_LOCAL0 * FACILITY_MULTIPLIER + SEVERITY_INFORMATIONAL
}


/// One RFC 5424 message: `<PRI>1 TIMESTAMP HOSTNAME APP-NAME PROCID MSGID - MSG`, the message being the ECS JSON.
pub fn format_message(header: &SyslogHeader, event: &EcsEvent) -> Result<String, ExportError> {
    let timestamp = event.timestamp.format(&Rfc3339)?;
    let json = to_json(event)?;
    Ok(format!(
        "<{}>1 {} {} {} {NIL_VALUE} {MESSAGE_ID} {NIL_VALUE} {}",
        priority(),
        timestamp,
        header_token(&header.hostname, MAX_HOSTNAME_LEN),
        header_token(&header.app_name, MAX_APP_NAME_LEN),
        json
    ))
}


/// RFC 6587 octet counting: the byte length, a space, then the message.
pub fn frame(message: &str) -> String {
    format!("{} {}", message.len(), message)
}


fn io_error(context: &str, source: std::io::Error) -> ExportError {
    ExportError::Io {
        context: context.to_string(),
        source,
    }
}


pub fn write_frames<Output: Write>(out: &mut Output, messages: &[String]) -> Result<(), ExportError> {
    messages
        .iter()
        .try_for_each(|message| out.write_all(frame(message).as_bytes()))
        .and_then(|()| out.flush())
        .map_err(|source| io_error("syslog write", source))
}


/// The local address of the same family as the target, so an IPv6 collector is reachable.
pub fn bind_address(target: &SocketAddr) -> &'static str {
    if target.is_ipv4() {
        UDP_BIND_V4
    } else {
        UDP_BIND_V6
    }
}


/// RFC 5426: one message per datagram, no framing; the socket binds the address family of the first resolved target.
pub fn send_datagrams(address: &str, messages: &[String]) -> Result<(), ExportError> {
    address
        .to_socket_addrs()
        .and_then(|mut resolved| resolved.next().ok_or(io::Error::from(io::ErrorKind::NotFound)))
        .and_then(|target| {
            UdpSocket::bind(bind_address(&target)).and_then(|socket| {
                messages
                    .iter()
                    .try_for_each(|message| socket.send_to(message.as_bytes(), target).map(|_sent| ()))
            })
        })
        .map_err(|source| io_error("syslog udp", source))
}
