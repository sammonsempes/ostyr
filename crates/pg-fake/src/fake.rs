use crate::types::{Handler, Shape};
use rustls::ServerConfig;
use std::io;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver, UnboundedSender};
use tokio_rustls::TlsAcceptor;


pub const MAX_MESSAGES: usize = 1000;


pub const TEXT_OID: i32 = 25;


pub const INT4_OID: i32 = 23;


pub const INT8_OID: i32 = 20;


pub const BINARY_FORMAT: usize = 1;


pub const INT8_BYTES: usize = 8;


pub const NO_SIZE: i16 = -1;


pub const LENGTH_FIELD_BYTES: usize = 4;


pub const CLEARTEXT_REQUEST: i32 = 3;


pub const SSL_REQUEST_BYTES: usize = 8;


#[derive(Clone)]
pub enum Reply {
    Done,
    Rows(Vec<Vec<String>>),
    IntRows(Vec<i32>),
    Typed {
        parameters: Vec<i32>,
        columns: Vec<i32>,
        rows: Vec<Vec<Option<Vec<u8>>>>,
    },
    Error(&'static str),
    Hang,
    Drop,
}


pub enum Mode {
    Tls(Arc<ServerConfig>),
}


pub struct Fake {
    pub port: u16,
    pub passwords: UnboundedReceiver<Vec<u8>>,
    pub statements: UnboundedReceiver<String>,
}


pub struct Session {
    sql: String,
    reply: Reply,
    skipping: bool,
}


pub fn frame(tag: u8, body: &[u8]) -> io::Result<Vec<u8>> {
    let length = i32::try_from(body.len() + LENGTH_FIELD_BYTES).map_err(io::Error::other)?;
    let mut bytes = vec![tag];
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(body);
    Ok(bytes)
}


pub fn error_frame(code: &str) -> io::Result<Vec<u8>> {
    let body = format!("SERROR\0C{code}\0Msecret-parameter-text\0\0");
    frame(b'E', body.as_bytes())
}


pub fn ready() -> io::Result<Vec<u8>> {
    frame(b'Z', b"I")
}


pub fn cstring(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|byte| *byte == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(bytes.get(..end).unwrap_or(bytes)).into_owned()
}


pub fn row_description(columns: usize, oid: i32) -> io::Result<Vec<u8>> {
    typed_row_description(&vec![oid; columns])
}


pub fn typed_row_description(oids: &[i32]) -> io::Result<Vec<u8>> {
    let count = i16::try_from(oids.len()).map_err(io::Error::other)?;
    let mut body = count.to_be_bytes().to_vec();
    oids.iter().for_each(|oid| {
        body.extend_from_slice(b"c\0");
        body.extend_from_slice(&0i32.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&oid.to_be_bytes());
        body.extend_from_slice(&NO_SIZE.to_be_bytes());
        body.extend_from_slice(&(-1i32).to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes());
    });
    frame(b'T', &body)
}


pub fn data_row(cells: &[Vec<u8>]) -> io::Result<Vec<u8>> {
    nullable_row(&cells.iter().cloned().map(Some).collect::<Vec<_>>())
}


pub fn int8_cell(value: i64) -> Option<Vec<u8>> {
    Some(value.to_be_bytes().to_vec())
}


pub fn nullable_row(cells: &[Option<Vec<u8>>]) -> io::Result<Vec<u8>> {
    let count = i16::try_from(cells.len()).map_err(io::Error::other)?;
    let mut body = count.to_be_bytes().to_vec();
    cells.iter().for_each(|cell| match cell {
        Some(bytes) => {
            body.extend_from_slice(&i32::try_from(bytes.len()).unwrap_or(i32::MAX).to_be_bytes());
            body.extend_from_slice(bytes);
        }
        None => body.extend_from_slice(&(-1i32).to_be_bytes()),
    });
    frame(b'D', &body)
}


pub fn rows_of(reply: &Reply) -> Option<Shape> {
    match reply {
        Reply::Rows(rows) => Some((
            vec![TEXT_OID; rows.first().map_or(0, Vec::len)],
            rows.iter()
                .map(|row| row.iter().map(|cell| Some(cell.as_bytes().to_vec())).collect())
                .collect(),
        )),
        Reply::IntRows(values) => Some((
            vec![INT4_OID],
            values.iter().map(|value| vec![Some(value.to_be_bytes().to_vec())]).collect(),
        )),
        Reply::Typed { columns, rows, .. } if !columns.is_empty() => Some((columns.clone(), rows.clone())),
        _ => None,
    }
}


pub fn rows_frames(reply: &Reply, with_description: bool) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    if let Some((oids, rows)) = rows_of(reply) {
        if with_description {
            out.extend(typed_row_description(&oids)?);
        }
        rows.iter().try_for_each(|row| nullable_row(row).map(|bytes| out.extend(bytes)))?;
    }
    Ok(out)
}


pub async fn read_message<Channel: AsyncRead + Unpin>(stream: &mut Channel) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut tag = [0u8; 1];
    if stream.read(&mut tag).await? == 0 {
        Ok(None)
    } else {
        let length = usize::try_from(stream.read_i32().await?).map_err(io::Error::other)?;
        let mut body = vec![0u8; length.saturating_sub(LENGTH_FIELD_BYTES)];
        stream.read_exact(&mut body).await?;
        Ok(Some((tag.first().copied().unwrap_or(0), body)))
    }
}


pub async fn simple(stream: &mut (impl AsyncWrite + Unpin), reply: &Reply) -> io::Result<()> {
    let mut out = rows_frames(reply, true)?;
    match reply {
        Reply::Error(code) => out.extend(error_frame(code)?),
        _ => out.extend(frame(b'C', b"OK\0")?),
    }
    out.extend(ready()?);
    stream.write_all(&out).await
}


pub async fn extended(stream: &mut (impl AsyncWrite + Unpin), session: &mut Session, tag: u8, body: &[u8]) -> io::Result<()> {
    let mut out = Vec::new();
    match tag {
        b'P' => {
            session.sql = cstring(body.get(cstring(body).len() + 1..).unwrap_or(&[]));
            if let Reply::Error(code) = session.reply {
                session.skipping = true;
                out.extend(error_frame(code)?);
            } else {
                out.extend(frame(b'1', &[])?);
            }
        }
        b'D' if body.first() == Some(&b'S') => {
            let parameters = parameter_count(&session.sql);
            let mut description = i16::try_from(parameters).map_err(io::Error::other)?.to_be_bytes().to_vec();
            (0..parameters).for_each(|index| description.extend_from_slice(&parameter_oid(&session.reply, index).to_be_bytes()));
            out.extend(frame(b't', &description)?);
            out.extend(match rows_of(&session.reply) {
                Some((oids, _)) => typed_row_description(&oids)?,
                None => frame(b'n', &[])?,
            });
        }
        b'B' => out.extend(frame(b'2', &[])?),
        b'E' => {
            out.extend(rows_frames(&session.reply, false)?);
            out.extend(frame(b'C', b"OK\0")?);
        }
        b'C' => out.extend(frame(b'3', &[])?),
        b'S' => {
            session.skipping = false;
            out.extend(ready()?);
        }
        _ => {}
    }
    stream.write_all(&out).await
}


pub const COUNT_BYTES: usize = 2;


pub fn be_u16(bytes: &[u8]) -> usize {
    bytes
        .get(..COUNT_BYTES)
        .and_then(|slice| <[u8; COUNT_BYTES]>::try_from(slice).ok())
        .map_or(0, |array| usize::from(u16::from_be_bytes(array)))
}


pub fn be_i32(bytes: &[u8]) -> i32 {
    bytes
        .get(..LENGTH_FIELD_BYTES)
        .and_then(|slice| <[u8; LENGTH_FIELD_BYTES]>::try_from(slice).ok())
        .map_or(0, i32::from_be_bytes)
}


pub fn parameter_oid(reply: &Reply, index: usize) -> i32 {
    match reply {
        Reply::Typed { parameters, .. } => parameters.get(index).copied().unwrap_or(TEXT_OID),
        _ => TEXT_OID,
    }
}


pub fn format_of(formats: &[u8], index: usize) -> usize {
    let count = be_u16(formats);
    let codes = formats.get(COUNT_BYTES..).unwrap_or(&[]);
    match count {
        0 => 0,
        1 => be_u16(codes),
        _ => be_u16(codes.get(index * COUNT_BYTES..).unwrap_or(&[])),
    }
}


pub fn render_param(bytes: &[u8], format: usize) -> String {
    match <[u8; INT8_BYTES]>::try_from(bytes) {
        Ok(array) if format == BINARY_FORMAT => i64::from_be_bytes(array).to_string(),
        _ => String::from_utf8_lossy(bytes).into_owned(),
    }
}


/// The parameters of a Bind message as text; a binary 8-byte parameter is shown as an int8.
pub fn bind_params(body: &[u8]) -> Vec<String> {
    let after_portal = body.get(cstring(body).len() + 1..).unwrap_or(&[]);
    let after_statement = after_portal.get(cstring(after_portal).len() + 1..).unwrap_or(&[]);
    let formats = be_u16(after_statement);
    let counted = after_statement.get(COUNT_BYTES + formats * COUNT_BYTES..).unwrap_or(&[]);
    let expected = be_u16(counted);
    let mut rest = counted.get(COUNT_BYTES..).unwrap_or(&[]);
    let mut params = Vec::new();
    while rest.len() >= LENGTH_FIELD_BYTES && params.len() < expected {
        let size = usize::try_from(be_i32(rest)).unwrap_or(0);
        let end = LENGTH_FIELD_BYTES + size;
        params.push(render_param(
            rest.get(LENGTH_FIELD_BYTES..end).unwrap_or(&[]),
            format_of(after_statement, params.len()),
        ));
        rest = rest.get(end..).unwrap_or(&[]);
    }
    params
}


pub async fn serve_messages<Channel: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut Channel,
    handler: &Handler,
    log: &UnboundedSender<String>,
) -> io::Result<()> {
    let mut session = Session {
        sql: String::new(),
        reply: Reply::Done,
        skipping: false,
    };
    let mut done = false;
    let mut handled = 0;
    while !done && handled < MAX_MESSAGES {
        handled += 1;
        match read_message(stream).await? {
            None => done = true,
            Some((b'X', _)) => done = true,
            Some((b'Q', body)) => {
                let sql = cstring(&body);
                log.send(sql.clone()).map_err(io::Error::other)?;
                let reply = handler(&sql);
                if matches!(reply, Reply::Hang) {
                    std::future::pending::<()>().await;
                }
                if matches!(reply, Reply::Drop) {
                    done = true;
                } else {
                    simple(stream, &reply).await?;
                }
            }
            Some((tag, body)) => {
                if tag == b'P' {
                    let sql = cstring(body.get(cstring(&body).len() + 1..).unwrap_or(&[]));
                    log.send(sql.clone()).map_err(io::Error::other)?;
                    session.reply = handler(&sql);
                    if matches!(session.reply, Reply::Hang) {
                        std::future::pending::<()>().await;
                    }
                }
                if tag == b'B' {
                    log.send(format!("PARAMS {}", bind_params(&body).join("|"))).map_err(io::Error::other)?;
                }
                if !session.skipping || tag == b'S' {
                    extended(stream, &mut session, tag, &body).await?;
                }
            }
        }
    }
    Ok(())
}


pub async fn authenticate<Channel: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut Channel,
    expected: &[u8],
    passwords: &UnboundedSender<Vec<u8>>,
) -> io::Result<bool> {
    let length = usize::try_from(stream.read_i32().await?).map_err(io::Error::other)?;
    let mut startup = vec![0u8; length.saturating_sub(LENGTH_FIELD_BYTES)];
    stream.read_exact(&mut startup).await?;
    stream.write_all(&frame(b'R', &CLEARTEXT_REQUEST.to_be_bytes())?).await?;
    let (_, body) = read_message(stream).await?.ok_or(io::Error::other("no password"))?;
    let received = body.strip_suffix(&[0]).unwrap_or(&body).to_vec();
    passwords.send(received.clone()).map_err(io::Error::other)?;
    if received == expected {
        stream.write_all(&frame(b'R', &0i32.to_be_bytes())?).await?;
        stream.write_all(&ready()?).await?;
        Ok(true)
    } else {
        stream.write_all(&error_frame("28P01")?).await?;
        Ok(false)
    }
}


pub async fn serve_connection(
    mut socket: TcpStream,
    mode: &Mode,
    expected: &[u8],
    handler: &Handler,
    passwords: &UnboundedSender<Vec<u8>>,
    log: &UnboundedSender<String>,
) -> io::Result<()> {
    let mut request = [0u8; SSL_REQUEST_BYTES];
    socket.read_exact(&mut request).await?;
    match mode {
        Mode::Tls(config) => {
            socket.write_all(b"S").await?;
            let mut tls = TlsAcceptor::from(Arc::clone(config)).accept(socket).await?;
            if authenticate(&mut tls, expected, passwords).await? {
                serve_messages(&mut tls, handler, log).await
            } else {
                Ok(())
            }
        }
    }
}


pub async fn start(mode: Mode, expected: &str, handler: Handler) -> io::Result<Fake> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let port = listener.local_addr()?.port();
    let (password_sender, passwords) = unbounded_channel();
    let (statement_sender, statements) = unbounded_channel();
    let expected_bytes = expected.as_bytes().to_vec();
    tokio::spawn(async move {
        let shared_mode = Arc::new(mode);
        let mut accepted = 0;
        while accepted < MAX_MESSAGES {
            accepted += 1;
            listener.accept().await.into_iter().for_each(|(socket, _)| {
                let shared = Arc::new((Arc::clone(&shared_mode), expected_bytes.clone(), Arc::clone(&handler)));
                let senders = (password_sender.clone(), statement_sender.clone());
                tokio::spawn(async move {
                    let (connection_mode, password, connection_handler) = &*shared;
                    if let Err(error) = serve_connection(socket, connection_mode, password, connection_handler, &senders.0, &senders.1).await {
                        tracing::debug!(%error, "fake connection ended");
                    }
                });
            });
        }
    });
    Ok(Fake { port, passwords, statements })
}


pub fn parameter_count(sql: &str) -> usize {
    sql.split('$')
        .skip(1)
        .filter_map(|tail| {
            let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
            digits.parse::<usize>().ok()
        })
        .max()
        .unwrap_or(0)
}
