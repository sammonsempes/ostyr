use crate::error::ParseError;
use crate::limits::Limits;
use crate::lldp::{bounded_list, malformed, parse_error, read_limited, replace_control_bytes, require_object};
use crate::lldp::{LIST_INTERFACE, LIST_LLDP, MAX_BLOCKS};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::io::Read;
use tracing::debug;


pub const MAX_PORT_NAME_BYTES: usize = 15;


pub const PORT_PUNCTUATION: &[u8] = b"._-@+";


#[derive(Deserialize)]
struct RawRoot<'a> {
    #[serde(borrow)]
    lldp: &'a RawValue,
}


#[derive(Deserialize)]
struct RawBlock<'a> {
    #[serde(borrow)]
    interface: Option<&'a RawValue>,
}


#[derive(Deserialize)]
struct RawNamed<'a> {
    #[serde(borrow)]
    name: Option<Cow<'a, str>>,
}


/// The distinct valid port names of an interface report, and how many entries were refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortList {
    pub ports: Vec<String>,
    pub refused_ports: usize,
}


/// ASCII allowlist for a Linux interface name that becomes an `lldpcli` argument: 1 to 15 bytes of `A-Za-z0-9._-@+`, no leading `-`, not `.` or `..`.
pub fn valid_port(name: &str) -> bool {
    let bytes_ok = name.bytes().all(|byte| byte.is_ascii_alphanumeric() || PORT_PUNCTUATION.contains(&byte));
    !name.is_empty() && name.len() <= MAX_PORT_NAME_BYTES && bytes_ok && !name.starts_with('-') && name != "." && name != ".."
}


fn block_names(block: &RawValue, limits: &Limits) -> Result<(Vec<Option<String>>, usize), ParseError> {
    require_object(block.get().as_bytes())?;
    let parsed: RawBlock = serde_json::from_str(block.get()).map_err(malformed)?;
    let list = bounded_list(parsed.interface, limits.max_interfaces).map_err(|error| parse_error(error, LIST_INTERFACE))?;
    let outcomes = list
        .iter()
        .map(|interface| serde_json::from_str::<RawNamed>(interface.get()))
        .collect::<Vec<_>>();
    let unreadable = outcomes.iter().filter(|outcome| outcome.is_err()).count();
    let names = outcomes
        .into_iter()
        .filter_map(Result::ok)
        .map(|interface| interface.name.map(Cow::into_owned))
        .collect();
    Ok((names, unreadable))
}


/// Port names from `lldpcli -f json0 show interfaces`, read through `take(max_bytes + 1)`, the interface list counted before it is built.
pub fn parse_ports<Source: Read>(reader: Source, limits: &Limits) -> Result<PortList, ParseError> {
    let mut buffer = read_limited(reader, limits.max_bytes)?;
    replace_control_bytes(&mut buffer);
    require_object(&buffer)?;
    let root: RawRoot = serde_json::from_slice(&buffer).map_err(malformed)?;
    let blocks = bounded_list(Some(root.lldp), MAX_BLOCKS).map_err(|error| parse_error(error, LIST_LLDP))?;
    let read = blocks.iter().map(|block| block_names(block, limits)).collect::<Result<Vec<_>, _>>()?;
    let unreadable = read.iter().map(|(_names, count)| count).sum::<usize>();
    let names = read.into_iter().flat_map(|(listed, _count)| listed).collect::<Vec<_>>();
    if unreadable > 0 {
        debug!(unreadable, "interface entries that are not objects");
    }
    let valid = names.iter().flatten().filter(|name| valid_port(name)).collect::<BTreeSet<_>>();
    let refused_ports = unreadable + names.len() - names.iter().flatten().filter(|name| valid_port(name)).count();
    Ok(PortList {
        ports: valid.into_iter().cloned().collect(),
        refused_ports,
    })
}
