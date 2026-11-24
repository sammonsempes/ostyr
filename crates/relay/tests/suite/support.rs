pub use crate::types::TestResult;
use core_audit::log::open_file_log;
use core_config::reload::ReloadEngine;
use relay::audit::{reload_context, shared_audit};
use relay::model::{Accepted, Halves, RelaySettings};
use relay::settings::open_settings_engine;
use relay::types::{AcceptFn, ConnectFn};
use std::collections::VecDeque;
use std::error::Error;
use std::io;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use tempfile::TempDir;
use tokio::io::{duplex, split, DuplexStream};


pub const BASE_YAML: &str = "listen: 0.0.0.0:443\nupstream: 10.0.0.1:8443\n";


pub const HUGE_SOFT: u64 = u64::MAX;


pub const DUPLEX_BYTES: usize = 65_536;


pub struct Rig {
    pub dir: TempDir,
    pub settings_path: PathBuf,
    pub audit_path: PathBuf,
    pub engine: Arc<ReloadEngine<RelaySettings>>,
}


pub fn rig(yaml: &str) -> Result<Rig, Box<dyn Error>> {
    let dir = tempfile::tempdir()?;
    let settings_path = dir.path().join("relay.yaml");
    let audit_path = dir.path().join("audit.log");
    std::fs::write(&settings_path, yaml)?;
    let log = Arc::new(open_file_log(&audit_path)?);
    let engine = Arc::new(open_settings_engine(
        settings_path.clone(),
        shared_audit(&log),
        reload_context(&settings_path),
        HUGE_SOFT,
    )?);
    Ok(Rig {
        dir,
        settings_path,
        audit_path,
        engine,
    })
}


pub fn audit_text(rig: &Rig) -> io::Result<String> {
    std::fs::read_to_string(&rig.audit_path)
}


pub fn link() -> (Halves, DuplexStream) {
    let (inner, outer) = duplex(DUPLEX_BYTES);
    (halves(inner), outer)
}


pub fn halves(stream: DuplexStream) -> Halves {
    let (read, write) = split(stream);
    Halves {
        read: Box::new(read),
        write: Box::new(write),
    }
}


pub fn peer(text: &str) -> Result<SocketAddr, Box<dyn Error>> {
    Ok(text.parse()?)
}


pub fn accepted(address: &str) -> Result<(Accepted, DuplexStream), Box<dyn Error>> {
    let (relay_side, test_side) = link();
    Ok((
        Accepted {
            halves: relay_side,
            peer: Ok(peer(address)?),
        },
        test_side,
    ))
}


pub fn scripted_accept(items: Vec<io::Result<Accepted>>, calls: Arc<AtomicUsize>) -> AcceptFn {
    let queue = Arc::new(Mutex::new(VecDeque::from(items)));
    Box::new(move || {
        calls.fetch_add(1, Ordering::SeqCst);
        let next = queue.lock().unwrap_or_else(PoisonError::into_inner).pop_front();
        Box::pin(async move {
            match next {
                Some(result) => result,
                None => std::future::pending().await,
            }
        })
    })
}


pub struct Upstreams {
    pub asked: Arc<Mutex<Vec<SocketAddr>>>,
    pub ends: Arc<Mutex<Vec<DuplexStream>>>,
}


pub fn recording_connect() -> (ConnectFn, Upstreams) {
    let asked = Arc::new(Mutex::new(Vec::new()));
    let ends = Arc::new(Mutex::new(Vec::new()));
    let recorded = Upstreams {
        asked: Arc::clone(&asked),
        ends: Arc::clone(&ends),
    };
    let connect: ConnectFn = Box::new(move |address| {
        asked.lock().unwrap_or_else(PoisonError::into_inner).push(address);
        let (relay_side, test_side) = link();
        ends.lock().unwrap_or_else(PoisonError::into_inner).push(test_side);
        Box::pin(async move { Ok(relay_side) })
    });
    (connect, recorded)
}


pub fn failing_connect() -> ConnectFn {
    Box::new(|_address| Box::pin(async { Err(io::Error::from(io::ErrorKind::ConnectionRefused)) }))
}


pub fn black_hole_connect() -> ConnectFn {
    Box::new(|_address| Box::pin(std::future::pending()))
}


pub async fn settle() {
    let rounds = 0..SETTLE_ROUNDS;
    for _round in rounds {
        tokio::task::yield_now().await;
    }
}


pub const SETTLE_ROUNDS: usize = 50;
