use crate::error::ParseError;
use crate::limits::Limits;
use crate::model::{ItemKey, Parsed, Resource, ResourceKind, SkipReason, Skipped};
use crate::proxmox::{
    count_skip, drop_shadowed_refusals, item_key, keep_refused_key, malformed, read_bounded, status_values, valid_display_name, MAX_BYTES_VALUE,
    MAX_CPU,
};
use serde::de::{DeserializeOwned, IgnoredAny};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::collections::HashSet;
use std::io::Read;


pub const MAX_ID_LEN: usize = 32;


pub const VM_LIST_CAP: usize = 4_000;


pub const HOST_LIST_CAP: usize = 2_500;


pub const BYTES_PER_MIB: u64 = 1_048_576;


pub const VM_PREFIX: &str = "vm-";


pub const HOST_PREFIX: &str = "host-";


#[derive(Deserialize)]
struct RawItem<'a> {
    #[serde(borrow)]
    vm: Option<&'a RawValue>,
    #[serde(borrow)]
    host: Option<&'a RawValue>,
    #[serde(borrow)]
    name: Option<&'a RawValue>,
    #[serde(borrow)]
    power_state: Option<&'a RawValue>,
    #[serde(borrow)]
    cpu_count: Option<&'a RawValue>,
    #[serde(borrow, rename = "memory_size_MiB", alias = "memory_size_mib")]
    memory_size_mib: Option<&'a RawValue>,
}


#[derive(Deserialize)]
struct RawId {
    vm: Option<String>,
    host: Option<String>,
}


/// One converted element: the resource and how many of its values were dropped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Converted {
    pub resource: Resource,
    pub name_dropped: usize,
    pub field_dropped: usize,
}


fn unparsable(_error: serde_json::Error) -> SkipReason {
    SkipReason::Unparsable
}


fn bad_field(_error: serde_json::Error) -> SkipReason {
    SkipReason::BadField
}


/// A field read as `T`; a wrong type (a nested array, an object, a string for a number) refuses the element alone.
pub fn typed<Wanted: DeserializeOwned>(raw: Option<&RawValue>) -> Result<Option<Wanted>, SkipReason> {
    raw.map(|value| serde_json::from_str::<Wanted>(value.get()).map_err(bad_field))
        .transpose()
}


pub fn list_cap(kind: ResourceKind) -> usize {
    if kind == ResourceKind::VsphereVm {
        VM_LIST_CAP
    } else {
        HOST_LIST_CAP
    }
}


/// `vm-<digits>` or `host-<digits>`, at most 32 bytes, ASCII only.
pub fn valid_id(kind: ResourceKind, text: &str) -> bool {
    let prefix = if kind == ResourceKind::VsphereVm { VM_PREFIX } else { HOST_PREFIX };
    text.len() <= MAX_ID_LEN
        && text
            .strip_prefix(prefix)
            .is_some_and(|digits| !digits.is_empty() && digits.chars().all(|next| next.is_ascii_digit()))
}


/// The identity of a refused element: only `vm` or `host` is read, every other field is ignored.
pub fn refused_id(kind: ResourceKind, raw: &RawValue) -> Option<ItemKey> {
    let found = serde_json::from_str::<RawId>(raw.get()).ok()?;
    let text = if kind == ResourceKind::VsphereVm { found.vm } else { found.host };
    text.filter(|identity| valid_id(kind, identity))
        .map(|identity| ItemKey { kind, key: identity })
}


/// One element, parsed alone. A value out of range or outside its documented set is dropped and counted, the element is kept.
pub fn convert_item(kind: ResourceKind, raw: &RawValue, limits: &Limits) -> Result<Converted, SkipReason> {
    let element: RawItem = serde_json::from_str(raw.get()).map_err(unparsable)?;
    let is_vm = kind == ResourceKind::VsphereVm;
    let id_raw = if is_vm { element.vm } else { element.host };
    let key = typed::<String>(id_raw)?.filter(|text| valid_id(kind, text)).ok_or(SkipReason::BadField)?;
    let name_text = typed::<String>(element.name)?;
    let name = name_text.as_deref().filter(|text| valid_display_name(text, limits)).map(str::to_owned);
    let power_text = typed::<String>(element.power_state)?;
    let status = power_text.as_deref().filter(|text| status_values(kind).contains(text)).map(str::to_owned);
    let cpu_raw = typed::<u64>(element.cpu_count.filter(|_| is_vm))?;
    let max_cpu = cpu_raw.filter(|count| *count <= MAX_CPU);
    let mem_raw = typed::<u64>(element.memory_size_mib.filter(|_| is_vm))?;
    let max_mem = mem_raw
        .and_then(|mebibytes| mebibytes.checked_mul(BYTES_PER_MIB))
        .filter(|bytes| *bytes <= MAX_BYTES_VALUE);
    let field_dropped = usize::from(power_text.is_some() && status.is_none())
        + usize::from(cpu_raw.is_some() && max_cpu.is_none())
        + usize::from(mem_raw.is_some() && max_mem.is_none());
    let name_dropped = usize::from(name_text.is_some() && name.is_none());
    let resource = Resource {
        kind,
        key,
        name,
        node: String::new(),
        status,
        max_cpu,
        max_mem,
        max_disk: None,
        template: false,
    };
    Ok(Converted {
        resource,
        name_dropped,
        field_dropped,
    })
}


/// Reads a top-level array: counted before built (at most the smaller of `max_items` and the API's own cap), then each element parsed alone.
pub fn parse_list<Source: Read>(reader: Source, limits: &Limits, kind: ResourceKind) -> Result<Parsed, ParseError> {
    let buffer = read_bounded(reader, limits)?;
    let count = serde_json::from_slice::<Vec<IgnoredAny>>(&buffer).map_err(malformed)?.len();
    let max = limits.max_items.min(list_cap(kind));
    if count > max {
        Err(ParseError::TooManyItems { count, max })?;
    }
    let elements = serde_json::from_slice::<Vec<&RawValue>>(&buffer).map_err(malformed)?;
    let mut parsed = Parsed {
        items: Vec::new(),
        skipped: Skipped::default(),
    };
    let mut seen = HashSet::new();
    for raw in &elements {
        match convert_item(kind, raw, limits) {
            Ok(done) if seen.insert(item_key(&done.resource)) => {
                parsed.skipped.name_dropped += done.name_dropped;
                parsed.skipped.field_dropped += done.field_dropped;
                parsed.items.push(done.resource);
            }
            Ok(_) => count_skip(&mut parsed.skipped, SkipReason::Duplicate),
            Err(reason) => {
                count_skip(&mut parsed.skipped, reason);
                keep_refused_key(&mut parsed.skipped, refused_id(kind, raw));
            }
        }
    }
    drop_shadowed_refusals(&mut parsed.skipped, &seen);
    let skipped_total =
        parsed.skipped.unparsable + parsed.skipped.bad_field + parsed.skipped.duplicate + parsed.skipped.name_dropped + parsed.skipped.field_dropped;
    if skipped_total > 0 {
        tracing::warn!(skipped_total, "vsphere items skipped");
    }
    Ok(parsed)
}


/// `GET /api/vcenter/vm`: an array of `{vm, name, power_state, cpu_count, memory_size_MiB}`.
pub fn parse_vms<Source: Read>(reader: Source, limits: &Limits) -> Result<Parsed, ParseError> {
    parse_list(reader, limits, ResourceKind::VsphereVm)
}


/// `GET /api/vcenter/host`: an array of `{host, name, connection_state, power_state}`.
pub fn parse_hosts<Source: Read>(reader: Source, limits: &Limits) -> Result<Parsed, ParseError> {
    parse_list(reader, limits, ResourceKind::VsphereHost)
}
