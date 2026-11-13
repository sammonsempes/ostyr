use crate::error::{ListError, ParseError};
use crate::limits::Limits;
use crate::model::{IdSubtype, NeighbourId, Observation, Parsed, SkipReason, Skipped};
use crate::text::valid_text;
use crate::types::RawList;
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::error::Category;
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::io::Read;
use std::net::IpAddr;


const NO_LIST: &str = "[]";


pub const OBJECT_START: u8 = b'{';


pub const MAX_BLOCKS: usize = 1;


pub const ID_LIST_MAX: usize = 1;


pub const NAME_LIST_MAX: usize = 1;


pub const MAC_TEXT_BYTES: usize = 17;


pub const MAC_OCTETS: usize = 6;


pub const MAC_OCTET_BYTES: usize = 2;


pub const MAC_SEPARATOR: char = ':';


pub const CONTROL_MAX: u8 = 0x1F;


pub const REPLACEMENT_BYTE: u8 = 0x7F;


pub const ALLOWED_CONTROLS: &[u8] = b"\t\n\r";


pub const LIST_LLDP: &str = "lldp";


pub const LIST_INTERFACE: &str = "interface";


pub const LIST_CHASSIS: &str = "chassis";


pub const LIST_PORT: &str = "port";


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
struct RawInterface<'a> {
    #[serde(borrow)]
    name: Option<Cow<'a, str>>,
    #[serde(borrow)]
    chassis: Option<&'a RawValue>,
    #[serde(borrow)]
    port: Option<&'a RawValue>,
}


#[derive(Deserialize)]
struct RawChassis<'a> {
    #[serde(borrow)]
    id: Option<&'a RawValue>,
    #[serde(borrow)]
    name: Option<&'a RawValue>,
    #[serde(borrow)]
    capability: Option<&'a RawValue>,
}


#[derive(Deserialize)]
struct RawPort<'a> {
    #[serde(borrow)]
    id: Option<&'a RawValue>,
}


#[derive(Deserialize)]
struct RawId<'a> {
    #[serde(borrow, rename = "type")]
    kind: Option<Cow<'a, str>>,
    #[serde(borrow)]
    value: Option<Cow<'a, str>>,
}


#[derive(Deserialize)]
struct RawName<'a> {
    #[serde(borrow)]
    value: Option<Cow<'a, str>>,
}


struct Context<'a> {
    local_host: &'a str,
    now: i64,
    limits: &'a Limits,
}


fn shape(error: serde_json::Error) -> ListError {
    ListError::Shape {
        category: error.classify(),
        line: error.line(),
        column: error.column(),
    }
}


fn malformed(error: serde_json::Error) -> ParseError {
    ParseError::Malformed {
        category: error.classify(),
        line: error.line(),
        column: error.column(),
    }
}


fn unparsable(_error: serde_json::Error) -> SkipReason {
    SkipReason::Unparsable
}


fn refused_list(_error: ListError) -> SkipReason {
    SkipReason::BadField
}


fn parse_error(error: ListError, list: &'static str) -> ParseError {
    match error {
        ListError::Shape { category, line, column } => ParseError::Malformed { category, line, column },
        ListError::TooMany { count, max } => ParseError::TooMany { list, count, max },
    }
}


/// A JSON array counted without allocating (`IgnoredAny` is zero-sized), its elements listed as raw text only when the count is within `max`.
pub fn bounded_list(raw: Option<&RawValue>, max: usize) -> Result<RawList<'_>, ListError> {
    let text = raw.map_or(NO_LIST, |value| value.get());
    let count = serde_json::from_str::<Vec<IgnoredAny>>(text).map_err(shape)?.len();
    if count > max {
        Err(ListError::TooMany { count, max })
    } else {
        serde_json::from_str::<RawList>(text).map_err(shape)
    }
}


/// The list of a neighbour level: a count above `max` refuses the whole report, a wrong shape yields `None` (the interface is skipped).
fn tolerant_list<'a>(raw: Option<&'a RawValue>, max: usize, list: &'static str) -> Result<Option<RawList<'a>>, ParseError> {
    match bounded_list(raw, max) {
        Ok(items) => Ok(Some(items)),
        Err(ListError::Shape { .. }) => Ok(None),
        Err(too_many) => Err(parse_error(too_many, list)),
    }
}


fn subtype_of(text: &str) -> Option<IdSubtype> {
    match text {
        "mac" => Some(IdSubtype::Mac),
        "ip" => Some(IdSubtype::Ip),
        "ifname" => Some(IdSubtype::IfName),
        "ifalias" => Some(IdSubtype::IfAlias),
        "local" => Some(IdSubtype::Local),
        "chassis" => Some(IdSubtype::Chassis),
        "port" => Some(IdSubtype::Port),
        _ => None,
    }
}


/// Six pairs of hex digits joined by `:`, lowercased.
pub fn normal_mac(text: &str) -> Option<String> {
    let well_formed = text.len() == MAC_TEXT_BYTES
        && text.split(MAC_SEPARATOR).count() == MAC_OCTETS
        && text
            .split(MAC_SEPARATOR)
            .all(|octet| octet.len() == MAC_OCTET_BYTES && octet.chars().all(|digit| digit.is_ascii_hexdigit()));
    well_formed.then(|| text.to_ascii_lowercase())
}


fn id_value(subtype: IdSubtype, value: &str, limits: &Limits) -> Result<String, SkipReason> {
    match subtype {
        IdSubtype::Mac => normal_mac(value).ok_or(SkipReason::BadField),
        IdSubtype::Ip => value
            .parse::<IpAddr>()
            .map(|address| address.to_string())
            .map_err(|_| SkipReason::BadField),
        _ => valid_text(value, limits.max_text_bytes)
            .then(|| value.to_owned())
            .ok_or(SkipReason::BadField),
    }
}


fn id_of(raw: Option<&RawValue>, limits: &Limits) -> Result<NeighbourId, SkipReason> {
    let entries = bounded_list(raw, ID_LIST_MAX).map_err(refused_list)?;
    let entry = entries.first().ok_or(SkipReason::BadField)?;
    let parsed: RawId = serde_json::from_str(entry.get()).map_err(unparsable)?;
    let subtype = parsed.kind.as_deref().and_then(subtype_of).ok_or(SkipReason::BadField)?;
    let value = parsed.value.as_deref().ok_or(SkipReason::BadField)?;
    Ok(NeighbourId {
        subtype,
        value: id_value(subtype, value, limits)?,
    })
}


fn name_of(raw: Option<&RawValue>, limits: &Limits) -> Result<(Option<String>, bool), SkipReason> {
    let entries = bounded_list(raw, NAME_LIST_MAX).map_err(refused_list)?;
    let name = entries
        .first()
        .map(|entry| {
            let parsed: RawName = serde_json::from_str(entry.get()).map_err(unparsable)?;
            Ok(parsed
                .value
                .as_deref()
                .filter(|text| valid_text(text, limits.max_text_bytes))
                .map(str::to_owned))
        })
        .transpose()
        .map(Option::flatten)?;
    Ok((name, !entries.is_empty()))
}


fn required_text(value: Option<&str>, limits: &Limits) -> Result<String, SkipReason> {
    value
        .filter(|text| valid_text(text, limits.max_text_bytes))
        .map(str::to_owned)
        .ok_or(SkipReason::BadField)
}


/// One neighbour: a chassis element and a port element parsed alone; the capability list is only counted.
fn convert(chassis_raw: &RawValue, port_raw: &RawValue, local_port: Option<&str>, context: &Context) -> Result<(Observation, bool), SkipReason> {
    let chassis: RawChassis = serde_json::from_str(chassis_raw.get()).map_err(unparsable)?;
    let port: RawPort = serde_json::from_str(port_raw.get()).map_err(unparsable)?;
    bounded_list(chassis.capability, context.limits.max_capabilities).map_err(refused_list)?;
    let (remote_name, listed) = name_of(chassis.name, context.limits)?;
    let dropped = remote_name.is_none() && listed;
    let observation = Observation {
        local_host: context.local_host.to_owned(),
        local_port: required_text(local_port, context.limits)?,
        remote_chassis: id_of(chassis.id, context.limits)?,
        remote_port: id_of(port.id, context.limits)?,
        remote_name,
        seen: context.now,
    };
    Ok((observation, dropped))
}


pub fn count_skip(skipped: &mut Skipped, reason: SkipReason) {
    match reason {
        SkipReason::Unparsable => skipped.unparsable += 1,
        SkipReason::BadField => skipped.bad_field += 1,
    }
}


fn read_neighbours(interface: &RawInterface, chassis: &[&RawValue], ports: &[&RawValue], context: &Context, parsed: &mut Parsed) {
    chassis.iter().zip(ports.iter()).for_each(
        |(chassis_raw, port_raw)| match convert(chassis_raw, port_raw, interface.name.as_deref(), context) {
            Ok((observation, dropped)) => {
                parsed.skipped.dropped_display += usize::from(dropped);
                parsed.observations.push(observation);
            }
            Err(reason) => count_skip(&mut parsed.skipped, reason),
        },
    );
}


/// serde derives read a JSON array as positional fields: only an object is accepted.
pub fn is_object(bytes: &[u8]) -> bool {
    bytes.iter().find(|byte| !byte.is_ascii_whitespace()) == Some(&OBJECT_START)
}


fn read_interface(raw: &RawValue, context: &Context, parsed: &mut Parsed) -> Result<(), ParseError> {
    match serde_json::from_str::<RawInterface>(raw.get())
        .ok()
        .filter(|_| is_object(raw.get().as_bytes()))
    {
        Some(interface) => {
            let max = context.limits.max_neighbours_per_interface;
            let chassis = tolerant_list(interface.chassis, max, LIST_CHASSIS)?;
            let ports = tolerant_list(interface.port, max, LIST_PORT)?;
            match chassis.zip(ports) {
                Some((chassis_list, port_list)) if chassis_list.len() == port_list.len() => {
                    read_neighbours(&interface, &chassis_list, &port_list, context, parsed);
                }
                _ => parsed.skipped.unparsable += 1,
            }
        }
        None => parsed.skipped.unparsable += 1,
    }
    Ok(())
}


fn require_object(bytes: &[u8]) -> Result<(), ParseError> {
    if is_object(bytes) {
        Ok(())
    } else {
        Err(ParseError::Malformed {
            category: Category::Data,
            line: 1,
            column: 1,
        })
    }
}


fn read_block(raw: &RawValue, context: &Context, parsed: &mut Parsed) -> Result<(), ParseError> {
    require_object(raw.get().as_bytes())?;
    let block: RawBlock = serde_json::from_str(raw.get()).map_err(malformed)?;
    let interfaces = bounded_list(block.interface, context.limits.max_interfaces).map_err(|error| parse_error(error, LIST_INTERFACE))?;
    interfaces.iter().try_for_each(|interface| read_interface(interface, context, parsed))
}


fn read_limited<Source: Read>(reader: Source, max_bytes: u64) -> Result<Vec<u8>, ParseError> {
    let mut buffer = Vec::new();
    let mut limited = reader.take(max_bytes.saturating_add(1));
    limited.read_to_end(&mut buffer).map_err(ParseError::Read)?;
    if limited.limit() == 0 {
        Err(ParseError::TooLarge { max: max_bytes })
    } else {
        Ok(buffer)
    }
}


fn check_host(local_host: &str, limits: &Limits) -> Result<(), ParseError> {
    if limits.max_links_per_port > limits.max_links_per_host {
        Err(ParseError::InvalidLimits {
            per_port: limits.max_links_per_port,
            per_host: limits.max_links_per_host,
        })
    } else if valid_text(local_host, limits.max_text_bytes) {
        Ok(())
    } else {
        Err(ParseError::InvalidHost)
    }
}


/// Replaces every control byte other than tab, line feed and carriage return by `0x7F` in place, returns how many were replaced.
pub fn replace_control_bytes(buffer: &mut [u8]) -> usize {
    buffer
        .iter_mut()
        .filter(|byte| **byte <= CONTROL_MAX && !ALLOWED_CONTROLS.contains(byte))
        .map(|byte| *byte = REPLACEMENT_BYTE)
        .count()
}


/// Parses a report already read, control bytes rewritten in place first: every list is counted before it is built, a malformed neighbour is skipped.
pub fn parse_buffer(buffer: &mut [u8], local_host: &str, now: i64, limits: &Limits) -> Result<Parsed, ParseError> {
    check_host(local_host, limits)?;
    let control_bytes = replace_control_bytes(buffer);
    require_object(buffer)?;
    let root: RawRoot = serde_json::from_slice(buffer).map_err(malformed)?;
    let blocks = bounded_list(Some(root.lldp), MAX_BLOCKS).map_err(|error| parse_error(error, LIST_LLDP))?;
    let context = Context { local_host, now, limits };
    let mut parsed = Parsed {
        observations: Vec::new(),
        skipped: Skipped {
            control_bytes,
            ..Skipped::default()
        },
    };
    blocks.iter().try_for_each(|block| read_block(block, &context, &mut parsed))?;
    let skipped_total = parsed.skipped.unparsable + parsed.skipped.bad_field + parsed.skipped.dropped_display;
    if skipped_total > 0 {
        tracing::warn!(skipped_total, "neighbours skipped");
    }
    Ok(parsed)
}


/// Parses `lldpcli -f json0 show neighbors details` from a reader, read through `take(max_bytes + 1)`.
pub fn parse_lldpd<Source: Read>(reader: Source, local_host: &str, now: i64, limits: &Limits) -> Result<Parsed, ParseError> {
    check_host(local_host, limits)?;
    let mut buffer = read_limited(reader, limits.max_bytes)?;
    parse_buffer(&mut buffer, local_host, now, limits)
}


/// Parses the report of one local port (`lldpcli -f json0 show neighbors ports <port> details`): its own byte cap, and a neighbour of another port refuses it.
pub fn parse_lldpd_port<Source: Read>(reader: Source, local_host: &str, local_port: &str, now: i64, limits: &Limits) -> Result<Parsed, ParseError> {
    check_host(local_host, limits)?;
    if limits.max_port_bytes > limits.max_bytes {
        Err(ParseError::InvalidPortBytes {
            per_port: limits.max_port_bytes,
            per_host: limits.max_bytes,
        })
    } else {
        let mut buffer = read_limited(reader, limits.max_port_bytes)?;
        let parsed = parse_buffer(&mut buffer, local_host, now, limits)?;
        let foreign = parsed
            .observations
            .iter()
            .filter(|observation| observation.local_port != local_port)
            .count();
        if foreign > 0 {
            Err(ParseError::WrongPort { count: foreign })
        } else {
            Ok(parsed)
        }
    }
}
