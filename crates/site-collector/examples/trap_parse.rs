use site_collector::model::{TrapDrop, TrapLimits, MAX_TRAP_BYTES};
use site_collector::snmp::parse_trap;
use std::error::Error;
use std::io::{stdout, Write};
use std::net::UdpSocket;


const USAGE: &str =
    "usage: trap_parse <listen-address:port> <datagram-count>; prints each parsed trap (Debug) or its drop reason, then the drop counts";


fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let address = arguments.next().ok_or(USAGE)?;
    let count: usize = arguments.next().ok_or(USAGE)?.parse()?;
    let socket = UdpSocket::bind(address)?;
    let mut buffer = vec![0u8; MAX_TRAP_BYTES + 1];
    let mut out = stdout();
    let limits = TrapLimits::default();
    let drops = (0..count).try_fold(Vec::new(), |mut seen: Vec<TrapDrop>, _| -> Result<Vec<TrapDrop>, Box<dyn Error>> {
        let (length, _) = socket.recv_from(&mut buffer)?;
        let datagram = buffer.get(..length).ok_or("short buffer")?;
        match parse_trap(datagram, &limits) {
            Ok(record) => writeln!(out, "{record:?}")?,
            Err(reason) => {
                writeln!(out, "dropped: {reason}")?;
                seen.push(reason);
            }
        }
        Ok(seen)
    })?;
    let counted = |reason: TrapDrop| drops.iter().filter(|seen| **seen == reason).count();
    writeln!(
        out,
        "too_large={} malformed={} unsupported={}",
        counted(TrapDrop::TooLarge),
        counted(TrapDrop::Malformed),
        counted(TrapDrop::Unsupported)
    )?;
    Ok(())
}
