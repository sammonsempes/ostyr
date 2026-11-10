use rustls::{ServerConfig, ServerConnection, StreamOwned};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::sync::Arc;
use std::thread::{spawn, JoinHandle};
use std::time::Duration;


const MAX_STEPS: usize = 64;


const DRAIN_BYTES: usize = 256;


const MAX_DRIPS: usize = 1000;


const DRIP_INTERVAL: Duration = Duration::from_millis(20);


const PLAIN_CAPABILITIES: &str = "250 stub\r\n";


const STARTTLS_CAPABILITIES: &str = "250-stub\r\n250 STARTTLS\r\n";


const SECURE_CAPABILITIES: &str = "250-stub\r\n250 AUTH PLAIN\r\n";


const NO_AUTH_CAPABILITIES: &str = "250 stub\r\n";


#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Starttls,
    Implicit,
    ImplicitNoAuth,
    ImplicitHangUp,
    PlainOnly,
}


#[derive(Default)]
pub struct Delivered {
    pub commands: Vec<String>,
    pub data: String,
}


pub struct Relay {
    pub port: u16,
    pub done: JoinHandle<io::Result<Delivered>>,
}


pub struct Drip {
    pub port: u16,
    pub held: JoinHandle<io::Result<()>>,
}


enum Next {
    Continue,
    Upgrade,
    Data,
    Quit,
}


fn answer(line: &str, capabilities: &str, reject: Option<&str>) -> (String, Next) {
    let upper = line.to_ascii_uppercase();
    match (upper.as_str(), reject) {
        (text, _) if text.starts_with("EHLO") => (capabilities.to_string(), Next::Continue),
        (text, _) if text.starts_with("STARTTLS") => ("220 ready\r\n".to_string(), Next::Upgrade),
        (text, _) if text.starts_with("DATA") => ("354 go\r\n".to_string(), Next::Data),
        (text, _) if text.starts_with("QUIT") => ("221 bye\r\n".to_string(), Next::Quit),
        (text, _) if text.starts_with("AUTH") => ("235 ok\r\n".to_string(), Next::Continue),
        (text, Some(refusal)) if text.starts_with("RCPT") => (format!("550 {refusal}\r\n"), Next::Continue),
        _ => ("250 ok\r\n".to_string(), Next::Continue),
    }
}


fn read_text<Stream: Read + Write>(reader: &mut BufReader<Stream>) -> io::Result<Option<String>> {
    let mut line = String::new();
    let count = match reader.read_line(&mut line) {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(0),
        other => other,
    }?;
    Ok((count > 0).then(|| line.trim_end().to_string()))
}


fn read_data<Stream: Read + Write>(reader: &mut BufReader<Stream>) -> io::Result<String> {
    let mut data = String::new();
    let mut finished = false;
    let mut steps = 0;
    while !finished && steps < MAX_STEPS {
        let line = read_text(reader)?.unwrap_or_else(|| "".to_owned());
        finished = line == ".";
        data.push_str(&line);
        data.push('\n');
        steps += 1;
    }
    Ok(data)
}


fn converse<Stream: Read + Write>(
    reader: &mut BufReader<Stream>,
    capabilities: &str,
    reject: Option<&str>,
    hang_up: bool,
    record: &mut Delivered,
) -> io::Result<Next> {
    let mut last = Next::Continue;
    let mut steps = 0;
    while matches!(last, Next::Continue) && steps < MAX_STEPS {
        last = match read_text(reader)? {
            None => Next::Quit,
            Some(line) => {
                let (reply, next) = answer(&line, capabilities, reject);
                record.commands.push(line);
                reader.get_mut().write_all(reply.as_bytes())?;
                reader.get_mut().flush()?;
                if matches!(next, Next::Data) {
                    record.data = read_data(reader)?;
                    reader.get_mut().write_all(b"250 queued\r\n")?;
                    reader.get_mut().flush()?;
                    if hang_up {
                        Next::Quit
                    } else {
                        Next::Continue
                    }
                } else {
                    next
                }
            }
        };
        steps += 1;
    }
    Ok(last)
}


fn phase<Stream: Read + Write>(
    stream: Stream,
    capabilities: &str,
    reject: Option<&str>,
    hang_up: bool,
    record: &mut Delivered,
) -> io::Result<(Next, Stream)> {
    let mut reader = BufReader::new(stream);
    reader.get_mut().write_all(b"220 stub\r\n")?;
    reader.get_mut().flush()?;
    let next = converse(&mut reader, capabilities, reject, hang_up, record)?;
    Ok((next, reader.into_inner()))
}


fn secure(tcp: TcpStream, config: Arc<ServerConfig>) -> io::Result<StreamOwned<ServerConnection, TcpStream>> {
    Ok(StreamOwned::new(ServerConnection::new(config).map_err(io::Error::other)?, tcp))
}


fn session(tcp: TcpStream, mode: Mode, config: Arc<ServerConfig>, reject: Option<&str>) -> io::Result<Delivered> {
    let mut record = Delivered::default();
    match mode {
        Mode::Implicit => {
            phase(secure(tcp, config)?, SECURE_CAPABILITIES, reject, false, &mut record)?;
        }
        Mode::ImplicitNoAuth => {
            phase(secure(tcp, config)?, NO_AUTH_CAPABILITIES, reject, false, &mut record)?;
        }
        Mode::ImplicitHangUp => {
            let (_next, stream) = phase(secure(tcp, config)?, SECURE_CAPABILITIES, reject, true, &mut record)?;
            let mut socket = stream.sock;
            socket.shutdown(Shutdown::Write)?;
            let mut buffer = vec![0; DRAIN_BYTES];
            let mut steps = 0;
            let mut open = true;
            while open && steps < MAX_STEPS {
                open = socket.read(&mut buffer)? > 0;
                steps += 1;
            }
        }
        Mode::PlainOnly => {
            phase(tcp, PLAIN_CAPABILITIES, reject, false, &mut record)?;
        }
        Mode::Starttls => {
            let (next, plain) = phase(tcp, STARTTLS_CAPABILITIES, reject, false, &mut record)?;
            if matches!(next, Next::Upgrade) {
                let mut reader = BufReader::new(secure(plain, config)?);
                converse(&mut reader, SECURE_CAPABILITIES, reject, false, &mut record)?;
            }
        }
    }
    Ok(record)
}


/// One connection handled; `reject` makes the server answer every RCPT with a 550 carrying that text.
pub fn spawn_relay(config: Arc<ServerConfig>, mode: Mode, reject: Option<&'static str>) -> io::Result<Relay> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let done = spawn(move || {
        let (tcp, _peer) = listener.accept()?;
        session(tcp, mode, config, reject)
    });
    Ok(Relay { port, done })
}


/// Writes `payload` once per interval until `release` fires or the client goes away: no single read of the client ever times out.
pub fn spawn_drip(release: Receiver<()>, payload: &'static [u8]) -> io::Result<Drip> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let held = spawn(move || {
        let (mut tcp, _peer) = listener.accept()?;
        let mut open = true;
        let mut count = 0;
        while open && count < MAX_DRIPS {
            let wrote = tcp.write_all(payload).and_then(|()| tcp.flush()).is_ok();
            open = wrote && release.recv_timeout(DRIP_INTERVAL) == Err(RecvTimeoutError::Timeout);
            count += 1;
        }
        Ok(())
    });
    Ok(Drip { port, held })
}


/// Writes `payload` in one go after accepting, then holds the connection until `release` fires.
pub fn spawn_flood(release: Receiver<()>, payload: Vec<u8>) -> io::Result<Drip> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let port = listener.local_addr()?.port();
    let held = spawn(move || {
        let (mut tcp, _peer) = listener.accept()?;
        let wrote = tcp.write_all(&payload).and_then(|()| tcp.flush());
        release.recv().map_err(io::Error::other)?;
        wrote.or(Ok(()))
    });
    Ok(Drip { port, held })
}
