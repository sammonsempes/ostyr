use rcgen::{generate_simple_self_signed, CertifiedKey};
use rustls::crypto::ring::default_provider;
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::error::Error;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};


pub const SERVER_NAME: &str = "localhost";


const BLOCK: usize = 65_536;


const MAX_BLOCKS: usize = 4096;


const FILLER: u8 = b'7';


pub struct Reply {
    pub status: u16,
    pub extra: &'static str,
    pub body: Vec<u8>,
    pub endless: bool,
}


pub struct Seen {
    pub request_line: String,
    pub authorization: Option<String>,
}


pub struct StandIn {
    pub port: u16,
    pub ca_pem: String,
    pub seen: JoinHandle<io::Result<Vec<Seen>>>,
}


pub fn reply(status: u16, body: &[u8]) -> Reply {
    Reply {
        status,
        extra: "",
        body: body.to_vec(),
        endless: false,
    }
}


fn headers_of<Stream: Read + Write>(reader: &mut BufReader<Stream>) -> io::Result<Vec<String>> {
    reader
        .by_ref()
        .lines()
        .take_while(|line| line.as_ref().is_ok_and(|text| !text.is_empty()))
        .collect()
}


fn write_reply<Stream: Write>(stream: &mut Stream, reply: &Reply) -> io::Result<()> {
    if reply.endless {
        stream.write_all(format!("HTTP/1.1 {} X\r\n{}connection: close\r\n\r\n", reply.status, reply.extra).as_bytes())?;
        let block = vec![FILLER; BLOCK];
        (0..MAX_BLOCKS).take_while(|_| stream.write_all(&block).is_ok()).count();
        Ok(())
    } else {
        let head = format!(
            "HTTP/1.1 {} X\r\n{}content-length: {}\r\nconnection: close\r\n\r\n",
            reply.status,
            reply.extra,
            reply.body.len()
        );
        stream.write_all(head.as_bytes())?;
        stream.write_all(&reply.body)?;
        stream.flush()
    }
}


fn serve_one<Stream: Read + Write>(stream: Stream, reply: &Reply) -> io::Result<Seen> {
    let mut reader = BufReader::new(stream);
    let headers = headers_of(&mut reader)?;
    write_reply(reader.get_mut(), reply)?;
    Ok(Seen {
        request_line: headers.first().cloned().ok_or_else(|| io::Error::other("no request line"))?,
        authorization: headers.iter().find_map(|line| {
            line.split_once(": ")
                .filter(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                .map(|(_, value)| value.to_owned())
        }),
    })
}


/// Serves one TLS connection per reply, blocking on each accept; the join returns what each request carried.
pub fn spawn_stand_in(replies: Vec<Reply>) -> Result<StandIn, Box<dyn Error>> {
    let CertifiedKey { cert, signing_key } = generate_simple_self_signed(vec![SERVER_NAME.to_string()])?;
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(signing_key.serialize_der()));
    let tls = Arc::new(
        ServerConfig::builder_with_provider(Arc::new(default_provider()))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(vec![cert.der().clone()], key)?,
    );
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let seen = spawn(move || {
        replies
            .iter()
            .map(|reply| {
                let (tcp, _peer) = listener.accept()?;
                serve_one(
                    StreamOwned::new(ServerConnection::new(tls.clone()).map_err(io::Error::other)?, tcp),
                    reply,
                )
            })
            .collect()
    });
    Ok(StandIn {
        port,
        ca_pem: cert.pem(),
        seen,
    })
}
