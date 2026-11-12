use site_collector::flow::parse_netflow_v5;
use site_collector::flow_model::{FlowBatch, FlowDrop, FlowLimits, MAX_TEMPLATE_DATAGRAM_BYTES};
use site_collector::template_model::TemplateCache;
use site_collector::template_parse::{parse_ipfix, parse_netflow_v9};
use std::error::Error;
use std::io::{stdin, stdout, Read, Write};
use std::net::{IpAddr, Ipv4Addr};


const USAGE: &str = "usage: flow_parse [v5|v9|ipfix] [datagram-file...]; one datagram per file in order (templates are cached across files) or one from stdin; prints each batch as JSON";


const EXPORTER: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);


fn read_datagram(path: Option<&String>) -> Result<Vec<u8>, Box<dyn Error>> {
    let read_limit = u64::try_from(MAX_TEMPLATE_DATAGRAM_BYTES)? + 1;
    let mut bytes = Vec::new();
    match path {
        Some(name) => std::fs::File::open(name)?.take(read_limit).read_to_end(&mut bytes)?,
        None => stdin().take(read_limit).read_to_end(&mut bytes)?,
    };
    Ok(bytes)
}


fn parse(kind: &str, bytes: &[u8], cache: &mut TemplateCache) -> Result<FlowBatch, FlowDrop> {
    let limits = FlowLimits::default();
    match kind {
        "v9" => parse_netflow_v9(bytes, EXPORTER, cache, 0, &limits),
        "ipfix" => parse_ipfix(bytes, EXPORTER, cache, 0, &limits),
        _ => parse_netflow_v5(bytes, &limits),
    }
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let versioned = arguments.first().is_some_and(|first| matches!(first.as_str(), "v5" | "v9" | "ipfix"));
    let kind = if versioned {
        arguments.first().map_or("v5", String::as_str)
    } else {
        "v5"
    };
    let files: Vec<Option<&String>> = if arguments.len() > usize::from(versioned) {
        arguments.iter().skip(usize::from(versioned)).map(Some).collect()
    } else {
        vec![None]
    };
    let mut cache = TemplateCache::default();
    files.into_iter().try_for_each(|path| {
        let bytes = read_datagram(path)?;
        let batch = parse(kind, &bytes, &mut cache).map_err(|reason| format!("dropped: {reason} ({USAGE})"))?;
        writeln!(stdout(), "{}", serde_json::to_string(&batch)?)?;
        Ok::<(), Box<dyn Error>>(())
    })
}
