use site_collector::flow::parse_netflow_v5;
use site_collector::flow_model::{FlowLimits, MAX_FLOW_DATAGRAM_BYTES};
use std::error::Error;
use std::io::{stdin, stdout, Read, Write};


const USAGE: &str = "usage: flow_parse [datagram-file]; reads one NetFlow v5 datagram from the file or stdin and prints the batch as JSON";


fn main() -> Result<(), Box<dyn Error>> {
    let read_limit = u64::try_from(MAX_FLOW_DATAGRAM_BYTES)? + 1;
    let mut bytes = Vec::new();
    match std::env::args().nth(1) {
        Some(path) => std::fs::File::open(path)?.take(read_limit).read_to_end(&mut bytes)?,
        None => stdin().take(read_limit).read_to_end(&mut bytes)?,
    };
    let batch = parse_netflow_v5(&bytes, &FlowLimits::default()).map_err(|reason| format!("dropped: {reason} ({USAGE})"))?;
    writeln!(stdout(), "{}", serde_json::to_string(&batch)?)?;
    Ok(())
}
