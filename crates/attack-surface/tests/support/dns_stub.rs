use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread::{spawn, JoinHandle};


const MAX_QUERIES: usize = 256;


const MAX_LABELS: usize = 16;


const PACKET_BYTES: usize = 512;


const HEADER_BYTES: usize = 12;


const ID_BYTES: usize = 2;


const TYPE_CLASS_BYTES: usize = 4;


const TYPE_A: u16 = 1;


const TYPE_AAAA: u16 = 28;


const TYPE_SOA: u16 = 6;


const NXDOMAIN: u8 = 3;


const RECURSION_AVAILABLE: u8 = 0x80;


const REPLY_FLAGS: u8 = 0x81;


const NAME_POINTER: [u8; 2] = [0xc0, 0x0c];


const CLASS_IN: [u8; 2] = [0, 1];


const TTL: [u8; 4] = [0, 0, 0, 60];


const SOA_TIMERS: [u8; 20] = [0; 20];


pub const SOA_MARKER: &str = "SOA-MARKER-0123456789";


#[derive(Clone)]
pub enum Mode {
    Answers(Vec<IpAddr>),
    NxDomain,
    Empty,
}


pub struct Stub {
    pub address: SocketAddr,
    pub seen: Arc<Mutex<Vec<(String, u16)>>>,
    stop: UdpSocket,
    worker: JoinHandle<()>,
}


fn qname(body: &[u8]) -> Option<(String, usize)> {
    let mut at = 0usize;
    let mut parts: Vec<String> = Vec::new();
    let mut done = false;
    let mut count = 0usize;
    while !done && count < MAX_LABELS {
        let length = usize::from(*body.get(at)?);
        if length == 0 {
            done = true;
        } else {
            parts.push(String::from_utf8_lossy(body.get(at + 1..at + 1 + length)?).into_owned());
            at += length + 1;
        }
        count += 1;
    }
    done.then(|| (parts.join("."), at + 1))
}


fn record(answer: &IpAddr) -> Result<Vec<u8>, std::num::TryFromIntError> {
    let (kind, data) = match answer {
        IpAddr::V4(v4) => (TYPE_A, v4.octets().to_vec()),
        IpAddr::V6(v6) => (TYPE_AAAA, v6.octets().to_vec()),
    };
    let length = u16::try_from(data.len())?;
    Ok([
        NAME_POINTER.as_slice(),
        &kind.to_be_bytes(),
        &CLASS_IN,
        &TTL,
        &length.to_be_bytes(),
        &data,
    ]
    .concat())
}


fn name_bytes(text: &str) -> Option<Vec<u8>> {
    let labels = text
        .split('.')
        .map(|label| {
            u8::try_from(label.len())
                .ok()
                .map(|length| [vec![length], label.as_bytes().to_vec()].concat())
        })
        .collect::<Option<Vec<_>>>()?
        .concat();
    Some([labels, vec![0]].concat())
}


fn soa_record() -> Option<Vec<u8>> {
    let data = [
        name_bytes(&format!("{SOA_MARKER}.example"))?,
        name_bytes("host.example")?,
        SOA_TIMERS.to_vec(),
    ]
    .concat();
    let length = u16::try_from(data.len()).ok()?;
    Some(
        [
            NAME_POINTER.as_slice(),
            &TYPE_SOA.to_be_bytes(),
            &CLASS_IN,
            &TTL,
            &length.to_be_bytes(),
            &data,
        ]
        .concat(),
    )
}


fn reply(query: &[u8], decide: fn(&str, usize) -> Mode, seen: &Arc<Mutex<Vec<(String, u16)>>>, index: usize) -> Option<Vec<u8>> {
    let identifier = query.get(..ID_BYTES)?;
    let body = query.get(HEADER_BYTES..)?;
    let (name, name_end) = qname(body)?;
    let question = body.get(..name_end + TYPE_CLASS_BYTES)?;
    let kind = u16::from_be_bytes([*question.get(name_end)?, *question.get(name_end + 1)?]);
    seen.lock().ok()?.push((name.clone(), kind));
    let mode = decide(&name, index);
    let answers: Vec<&IpAddr> = match &mode {
        Mode::Answers(all) => all
            .iter()
            .filter(|answer| (kind == TYPE_A) == answer.is_ipv4() && (kind == TYPE_A || kind == TYPE_AAAA))
            .collect(),
        Mode::NxDomain | Mode::Empty => Vec::new(),
    };
    let missing = matches!(mode, Mode::NxDomain);
    let rcode = if missing { NXDOMAIN } else { 0 };
    let authority = if missing { soa_record()? } else { Vec::new() };
    let records = answers.iter().copied().map(record).collect::<Result<Vec<_>, _>>().ok()?.concat();
    let answer_count = u16::try_from(answers.len()).ok()?;
    let authority_count = u16::from(missing);
    let header = [
        identifier,
        &[REPLY_FLAGS, RECURSION_AVAILABLE | rcode, 0, 1],
        &answer_count.to_be_bytes(),
        &authority_count.to_be_bytes(),
        &[0, 0],
    ]
    .concat();
    Some([header, question.to_vec(), records, authority].concat())
}


pub fn serve(decide: fn(&str, usize) -> Mode) -> Result<Stub, std::io::Error> {
    let socket = UdpSocket::bind("127.0.0.1:0")?;
    let address = socket.local_addr()?;
    let stop = UdpSocket::bind("127.0.0.1:0")?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let worker = spawn(move || {
        let mut buffer = [0u8; PACKET_BYTES];
        let answered = (0..MAX_QUERIES)
            .map(|index| {
                socket
                    .recv_from(&mut buffer)
                    .ok()
                    .map(|(length, peer)| (index, buffer.get(..length).map(<[u8]>::to_vec), peer))
            })
            .take_while(|received| {
                received
                    .as_ref()
                    .is_some_and(|(_, packet, _)| packet.as_ref().is_some_and(|bytes| !bytes.is_empty()))
            })
            .flatten()
            .filter_map(|(index, packet, peer)| packet.and_then(|bytes| reply(&bytes, decide, &log, index)).map(|bytes| (bytes, peer)))
            .filter(|(bytes, peer)| socket.send_to(bytes, peer).is_ok())
            .count();
        assert!(answered <= MAX_QUERIES);
    });
    Ok(Stub { address, seen, stop, worker })
}


pub fn finish(stub: Stub) -> Result<Vec<(String, u16)>, Box<dyn std::error::Error>> {
    stub.stop.send_to(&[], stub.address)?;
    stub.worker.join().map_err(|_| "stub thread failed")?;
    let seen = stub.seen.lock().map_err(|_| "stub log poisoned")?.clone();
    Ok(seen)
}
