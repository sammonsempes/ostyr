#[path = "common/types.rs"]
mod types;


use std::io::{self, Write};
use std::net::{SocketAddr, UdpSocket};
use std::ops::ControlFlow;
use std::sync::{Arc, LazyLock, Mutex, PoisonError};
use std::thread::spawn;
use std::time::Duration;
use synthetic_checks::dns::dns_resolve;
use synthetic_checks::serve::{log_dispatch, SILENCED_TARGETS};
use tracing::dispatcher::with_default;
use tracing::Dispatch;
use tracing_subscriber::fmt::writer::BoxMakeWriter;
use types::TestResult;


const SECRET_NAME: &str = "secret-host.internal";


const HEADER_LEN: usize = 12;


const ID_LEN: usize = 2;


const SILENCED_COUNT: usize = 3;


const MAX_LABELS: usize = 64;


const TYPE_AND_CLASS_LEN: usize = 4;


const MAX_DATAGRAM: usize = 512;


const STUB_QUERIES: usize = 4;


const STUB_WAIT: Duration = Duration::from_secs(3);


const LOOKUP_LIMIT: Duration = Duration::from_secs(2);


const ANSWER_CAP: usize = 4;


const FLAGS_RESPONSE: [u8; 2] = [0x81, 0x80];


const COUNTS_ONE_QUESTION_ONE_ANSWER: [u8; 8] = [0, 1, 0, 1, 0, 0, 0, 0];


const FOREIGN_CLASS_ANSWER: [u8; 16] = [0xc0, 0x0c, 0, 1, 0, 3, 0, 0, 0, 0, 0, 4, 127, 0, 0, 1];


static ANCHOR: LazyLock<Dispatch> = LazyLock::new(|| Dispatch::new(tracing_subscriber::fmt().with_writer(io::sink).finish()));


struct Capture(Arc<Mutex<Vec<u8>>>);


impl Write for Capture {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner).extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}


fn captured_dispatch() -> (Dispatch, Arc<Mutex<Vec<u8>>>) {
    LazyLock::force(&ANCHOR);
    let buffer = Arc::new(Mutex::new(Vec::new()));
    let sink = Arc::clone(&buffer);
    (log_dispatch(BoxMakeWriter::new(move || Capture(Arc::clone(&sink)))), buffer)
}


fn text_of(buffer: &Mutex<Vec<u8>>) -> String {
    String::from_utf8_lossy(&buffer.lock().unwrap_or_else(PoisonError::into_inner)).into_owned()
}


fn question_end(query: &[u8]) -> usize {
    let flow = (0..MAX_LABELS).try_fold(HEADER_LEN, |position, _label| match query.get(position) {
        Some(0) | None => ControlFlow::Break(position + 1),
        Some(length) => ControlFlow::Continue(position + 1 + usize::from(*length)),
    });
    match flow {
        ControlFlow::Break(end) | ControlFlow::Continue(end) => end + TYPE_AND_CLASS_LEN,
    }
}


fn foreign_class_reply(query: &[u8]) -> Option<Vec<u8>> {
    let mut reply = query.get(..ID_LEN)?.to_vec();
    reply.extend_from_slice(&FLAGS_RESPONSE);
    reply.extend_from_slice(&COUNTS_ONE_QUESTION_ONE_ANSWER);
    reply.extend_from_slice(query.get(HEADER_LEN..question_end(query))?);
    reply.extend_from_slice(&FOREIGN_CLASS_ANSWER);
    Some(reply)
}


fn stub_dns() -> Result<(SocketAddr, std::thread::JoinHandle<usize>), Box<dyn std::error::Error>> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    socket.set_read_timeout(Some(STUB_WAIT))?;
    let address = socket.local_addr()?;
    let handle = spawn(move || {
        (0..STUB_QUERIES)
            .map_while(|_query| {
                let mut datagram = [0; MAX_DATAGRAM];
                socket.recv_from(&mut datagram).ok().and_then(|(length, peer)| {
                    datagram
                        .get(..length)
                        .and_then(foreign_class_reply)
                        .map(|reply| socket.send_to(&reply, peer))
                })
            })
            .count()
    });
    Ok((address, handle))
}


#[test]
fn a_foreign_class_answer_leaves_no_name_and_no_resolver_text_in_the_log() -> TestResult {
    let (stub, handle) = stub_dns()?;
    let (dispatch, buffer) = captured_dispatch();
    let outcome = with_default(&dispatch, || {
        tracing::info!("marker");
        dns_resolve(Some(stub), SECRET_NAME, LOOKUP_LIMIT, ANSWER_CAP)
    });
    let answered = handle.join().map_err(|_panic| "the stub panicked")?;
    let logged = text_of(&buffer);
    assert!(outcome.is_err());
    assert!(answered > 0, "the stub saw no query");
    assert!(logged.contains("marker"), "{logged}");
    assert!(
        !logged.contains(SECRET_NAME) && !logged.to_ascii_lowercase().contains("hickory"),
        "{logged}"
    );
    Ok(())
}


#[test]
fn every_silenced_target_is_dropped_at_every_level_and_other_targets_keep_info() -> TestResult {
    let (dispatch, buffer) = captured_dispatch();
    with_default(&dispatch, || {
        tracing::error!(target: "hickory_resolver::name_server_pool", "{SECRET_NAME}");
        tracing::error!(target: "hickory_proto::udp", "{SECRET_NAME}");
        tracing::error!(target: "hickory_net::udp", "{SECRET_NAME}");
        tracing::info!(target: "synthetic_checks::serve", "kept");
        tracing::debug!(target: "synthetic_checks::serve", "too chatty");
    });
    let logged = text_of(&buffer);
    assert_eq!(SILENCED_TARGETS.len(), SILENCED_COUNT);
    assert!(
        logged.contains("kept") && !logged.contains("too chatty") && !logged.contains(SECRET_NAME),
        "{logged}"
    );
    Ok(())
}
