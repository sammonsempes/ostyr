use crate::accept::accept_bounded;
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread::{spawn, JoinHandle};


const HEADER_END: &[u8] = b"\r\n\r\n";


const CHUNK: usize = 4096;


const MAX_READS: usize = 1000;


const ZERO: u8 = 0;


/// One scripted answer; `declared` is the Content-Length sent, which may exceed the body so the connection ends early.
pub struct Canned {
    pub status: &'static str,
    pub headers: Vec<(&'static str, &'static str)>,
    pub body: Vec<u8>,
    pub declared: usize,
}


pub fn ok(body: &str) -> Canned {
    Canned {
        status: "200 OK",
        headers: Vec::new(),
        body: body.as_bytes().to_vec(),
        declared: body.len(),
    }
}


pub fn failing(status: &'static str, code: Option<&'static str>) -> Canned {
    Canned {
        status,
        headers: code.map(|value| ("X-ClickHouse-Exception-Code", value)).into_iter().collect(),
        body: Vec::new(),
        declared: 0,
    }
}


pub fn cut(body: &str) -> Canned {
    Canned {
        declared: body.len() + CHUNK,
        ..ok(body)
    }
}


fn read_head(stream: &mut TcpStream) -> io::Result<String> {
    let mut received = Vec::new();
    let mut chunk = [ZERO; CHUNK];
    let mut reads = 0;
    while !received.windows(HEADER_END.len()).any(|window| window == HEADER_END) && reads < MAX_READS {
        reads += 1;
        let count = stream.read(&mut chunk)?;
        received.extend_from_slice(chunk.get(..count).unwrap_or(&[]));
    }
    Ok(String::from_utf8_lossy(&received).into_owned())
}


fn answer(stream: &mut TcpStream, canned: &Canned) -> io::Result<()> {
    let extra: String = canned.headers.iter().map(|(name, value)| format!("{name}: {value}\r\n")).collect();
    let head = format!(
        "HTTP/1.1 {}\r\nContent-Length: {}\r\n{extra}Connection: close\r\n\r\n",
        canned.status, canned.declared
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(&canned.body)?;
    stream.flush()
}


/// Answers one connection per scripted reply, in order, and returns the request heads it saw.
pub fn serve_replies(listener: TcpListener, replies: Vec<Canned>) -> JoinHandle<io::Result<Vec<String>>> {
    spawn(move || {
        replies.iter().try_fold(Vec::new(), |mut seen, canned| {
            let mut stream = accept_bounded(&listener)?;
            seen.push(read_head(&mut stream)?);
            answer(&mut stream, canned)?;
            Ok(seen)
        })
    })
}
