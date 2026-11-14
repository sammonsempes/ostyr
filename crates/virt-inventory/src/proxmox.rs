use crate::error::ParseError;
use crate::limits::Limits;
use crate::model::{ItemKey, Parsed, PathPrivileges, Permissions, Resource, ResourceKind, SkipReason, Skipped};
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_with::{DeserializeAs, Map, Same};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::io::Read;


pub const MIN_VMID: u64 = 100;


pub const MAX_VMID: u64 = 999_999_999;


pub const MAX_CPU: u64 = 65_536;


pub const MAX_BYTES_VALUE: u64 = 9_007_199_254_740_992;


pub const MAX_PRIVILEGE_LEN: usize = 64;


pub const MAX_NODE_LEN: usize = 63;


pub const MAX_STORAGE_LEN: usize = 64;


pub const MAX_SEGMENT_LEN: usize = 64;


pub const MAX_PATH_SEGMENTS: usize = 8;


pub const MAX_FLAG: u64 = 1;


pub const NO_GRANTS: usize = 0;


pub const KIND_QEMU: &str = "qemu";


pub const KIND_LXC: &str = "lxc";


pub const KIND_NODE: &str = "node";


pub const KIND_STORAGE: &str = "storage";


#[derive(Deserialize)]
struct RawData<'a> {
    #[serde(borrow)]
    data: &'a RawValue,
}


#[derive(Deserialize)]
struct RawResource<'a> {
    #[serde(borrow, rename = "type")]
    kind: Option<Cow<'a, str>>,
    vmid: Option<u64>,
    #[serde(borrow)]
    name: Option<Cow<'a, str>>,
    #[serde(borrow)]
    node: Option<Cow<'a, str>>,
    #[serde(borrow)]
    storage: Option<Cow<'a, str>>,
    #[serde(borrow)]
    status: Option<Cow<'a, str>>,
    maxcpu: Option<u64>,
    maxmem: Option<u64>,
    maxdisk: Option<u64>,
    template: Option<u64>,
}


#[derive(Deserialize)]
struct RawKind<'a> {
    #[serde(borrow, rename = "type")]
    kind: Option<Cow<'a, str>>,
}


#[derive(Deserialize)]
struct RawVmid {
    vmid: Option<u64>,
}


#[derive(Deserialize)]
struct RawNode<'a> {
    #[serde(borrow)]
    node: Option<Cow<'a, str>>,
}


#[derive(Deserialize)]
struct RawStorageKey<'a> {
    #[serde(borrow)]
    node: Option<Cow<'a, str>>,
    #[serde(borrow)]
    storage: Option<Cow<'a, str>>,
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


/// Reads at most `max_bytes` (one more is `TooLarge`).
pub fn read_bounded<Source: Read>(reader: Source, limits: &Limits) -> Result<Vec<u8>, ParseError> {
    let mut buffer = Vec::new();
    let mut limited = reader.take(limits.max_bytes.saturating_add(1));
    limited.read_to_end(&mut buffer).map_err(ParseError::Read)?;
    if limited.limit() == 0 {
        Err(ParseError::TooLarge { max: limits.max_bytes })?;
    }
    Ok(buffer)
}


/// A JSON object counted entry by entry without allocating (`IgnoredAny` is zero-sized).
pub fn count_entries(text: &str) -> Result<usize, ParseError> {
    let mut counter = serde_json::Deserializer::from_str(text);
    let entries: Vec<(IgnoredAny, IgnoredAny)> = Map::<Same, Same>::deserialize_as(&mut counter).map_err(malformed)?;
    Ok(entries.len())
}


pub fn item_key(resource: &Resource) -> ItemKey {
    ItemKey {
        kind: resource.kind,
        key: resource.key.clone(),
    }
}


pub fn kind_of(text: &str) -> Option<ResourceKind> {
    match text {
        KIND_QEMU => Some(ResourceKind::Qemu),
        KIND_LXC => Some(ResourceKind::Lxc),
        KIND_NODE => Some(ResourceKind::Node),
        KIND_STORAGE => Some(ResourceKind::Storage),
        _ => None,
    }
}


/// A node name is a hostname label: ASCII letters, digits and inner `-`, 1 to 63 bytes.
pub fn valid_node(text: &str) -> bool {
    text.len() <= MAX_NODE_LEN
        && text.chars().next().is_some_and(|first| first.is_ascii_alphanumeric())
        && text.chars().last().is_some_and(|last| last.is_ascii_alphanumeric())
        && text.chars().all(|next| next.is_ascii_alphanumeric() || next == '-')
}


/// A storage id: ASCII letter first, then letters, digits, `.`, `_` or `-`, at most 64 bytes.
pub fn valid_storage(text: &str) -> bool {
    text.len() <= MAX_STORAGE_LEN
        && text.chars().next().is_some_and(|first| first.is_ascii_alphabetic())
        && text.chars().all(|next| next.is_ascii_alphanumeric() || matches!(next, '.' | '_' | '-'))
}


pub fn valid_segment(text: &str) -> bool {
    (1..=MAX_SEGMENT_LEN).contains(&text.len())
        && text
            .chars()
            .all(|next| next.is_ascii_alphanumeric() || matches!(next, '.' | '_' | '@' | ':' | '-'))
}


/// An ACL path: `/` then at most 8 segments of ASCII `[A-Za-z0-9._@:-]`, 1 to 64 bytes each.
pub fn valid_acl_path(text: &str) -> bool {
    text.strip_prefix('/')
        .is_some_and(|rest| rest.is_empty() || (rest.split('/').count() <= MAX_PATH_SEGMENTS && rest.split('/').all(valid_segment)))
}


/// A display name: ASCII graphic characters and single inner spaces, within the text cap.
pub fn valid_display_name(text: &str, limits: &Limits) -> bool {
    text.len() <= limits.max_text_bytes
        && !text.is_empty()
        && !text.starts_with(' ')
        && !text.ends_with(' ')
        && !text.contains("  ")
        && text.chars().all(|next| next.is_ascii_graphic() || next == ' ')
}


/// The identity of an element from its kind, vmid, node and storage; `None` when a needed part is missing or refused.
pub fn identity_of(kind: ResourceKind, vmid: Option<u64>, node: Option<&str>, storage: Option<&str>) -> Option<String> {
    let folded = node.filter(|name| valid_node(name)).map(str::to_ascii_lowercase);
    let node_name = folded.as_deref();
    match kind {
        ResourceKind::Qemu | ResourceKind::Lxc => vmid.filter(|id| (MIN_VMID..=MAX_VMID).contains(id)).map(|id| id.to_string()),
        ResourceKind::Node => node_name.map(str::to_owned),
        ResourceKind::Storage => node_name
            .zip(storage.filter(|name| valid_storage(name)))
            .map(|(host, name)| format!("{host}/{name}")),
    }
}


/// The `status` values Proxmox documents for `/cluster/resources`: guests, nodes and storages.
pub const STATUS_VALUES: [&str; 7] = ["running", "stopped", "paused", "unknown", "online", "offline", "available"];


fn status_of(value: Option<&str>) -> Result<Option<String>, SkipReason> {
    value
        .map(|text| {
            if STATUS_VALUES.contains(&text) {
                Ok(text.to_owned())
            } else {
                Err(SkipReason::BadField)
            }
        })
        .transpose()
}


fn number_of(value: Option<u64>, max: u64) -> Result<Option<u64>, SkipReason> {
    value
        .map(|number| if number <= max { Ok(number) } else { Err(SkipReason::BadField) })
        .transpose()
}


/// One resource element, parsed alone: a known type, its identity and a node; numbers as integers within range.
pub fn convert_resource(raw: &RawValue, limits: &Limits) -> Result<(Resource, bool), SkipReason> {
    let element: RawResource = serde_json::from_str(raw.get()).map_err(unparsable)?;
    let kind = element.kind.as_deref().and_then(kind_of).ok_or(SkipReason::OtherType)?;
    let key = identity_of(kind, element.vmid, element.node.as_deref(), element.storage.as_deref()).ok_or(SkipReason::BadField)?;
    let node = element.node.as_deref().filter(|name| valid_node(name)).ok_or(SkipReason::BadField)?;
    let template = number_of(element.template, MAX_FLAG)?.is_some_and(|flag| flag == MAX_FLAG);
    let name_source = if kind == ResourceKind::Storage {
        element.storage.as_deref()
    } else {
        element.name.as_deref()
    };
    let name = name_source.filter(|text| valid_display_name(text, limits)).map(str::to_owned);
    let name_dropped = name_source.is_some() && name.is_none();
    let resource = Resource {
        kind,
        key,
        name,
        node: node.to_ascii_lowercase(),
        status: status_of(element.status.as_deref())?,
        max_cpu: number_of(element.maxcpu, MAX_CPU)?,
        max_mem: number_of(element.maxmem, MAX_BYTES_VALUE)?,
        max_disk: number_of(element.maxdisk, MAX_BYTES_VALUE)?,
        template,
    };
    Ok((resource, name_dropped))
}


/// The identity of a refused element: only its type, then only the identity parts of that type are read; every other field is ignored.
pub fn refused_key(raw: &RawValue) -> Option<ItemKey> {
    let text = raw.get();
    let typed = serde_json::from_str::<RawKind>(text).ok()?;
    let kind = typed.kind.as_deref().and_then(kind_of)?;
    let key = match kind {
        ResourceKind::Qemu | ResourceKind::Lxc => {
            let guest = serde_json::from_str::<RawVmid>(text).ok()?;
            identity_of(kind, guest.vmid, None, None)
        }
        ResourceKind::Node => {
            let host = serde_json::from_str::<RawNode>(text).ok()?;
            identity_of(kind, None, host.node.as_deref(), None)
        }
        ResourceKind::Storage => {
            let volume = serde_json::from_str::<RawStorageKey>(text).ok()?;
            identity_of(kind, None, volume.node.as_deref(), volume.storage.as_deref())
        }
    };
    key.map(|identity| ItemKey { kind, key: identity })
}


/// A refused element whose identity cannot be kept is counted in `key_lost`: that count replaces any per-element log.
pub fn keep_refused_key(skipped: &mut Skipped, key: Option<ItemKey>) {
    match key {
        Some(kept) => skipped.refused_keys.push(kept),
        None => skipped.key_lost += 1,
    }
}


pub fn count_skip(skipped: &mut Skipped, reason: SkipReason) {
    match reason {
        SkipReason::Unparsable => skipped.unparsable += 1,
        SkipReason::BadField => skipped.bad_field += 1,
        SkipReason::Duplicate => skipped.duplicate += 1,
        SkipReason::OtherType => skipped.other_type += 1,
    }
}


/// A refused key equal to a kept key is dropped and counted `duplicate`: the kept element wins, whatever the order in the list.
pub fn drop_shadowed_refusals(skipped: &mut Skipped, kept: &HashSet<ItemKey>) {
    let before = skipped.refused_keys.len();
    skipped.refused_keys.retain(|key| !kept.contains(key));
    skipped.duplicate += before - skipped.refused_keys.len();
}


/// Reads the `data` array of `GET /cluster/resources`: counted before built, then each element parsed alone; the first of a repeated identity is kept.
pub fn parse_resources<Source: Read>(reader: Source, limits: &Limits) -> Result<Parsed, ParseError> {
    let buffer = read_bounded(reader, limits)?;
    let root: RawData = serde_json::from_slice(&buffer).map_err(malformed)?;
    let count = serde_json::from_str::<Vec<IgnoredAny>>(root.data.get()).map_err(malformed)?.len();
    if count > limits.max_items {
        Err(ParseError::TooManyItems {
            count,
            max: limits.max_items,
        })?;
    }
    let elements = serde_json::from_str::<Vec<&RawValue>>(root.data.get()).map_err(malformed)?;
    let mut parsed = Parsed {
        items: Vec::new(),
        skipped: Skipped::default(),
    };
    let mut seen = HashSet::new();
    for raw in &elements {
        match convert_resource(raw, limits) {
            Ok((item, name_dropped)) if seen.insert(item_key(&item)) => {
                parsed.skipped.name_dropped += usize::from(name_dropped);
                parsed.items.push(item);
            }
            Ok(_) => count_skip(&mut parsed.skipped, SkipReason::Duplicate),
            Err(SkipReason::OtherType) => count_skip(&mut parsed.skipped, SkipReason::OtherType),
            Err(reason) => {
                count_skip(&mut parsed.skipped, reason);
                keep_refused_key(&mut parsed.skipped, refused_key(raw));
            }
        }
    }
    drop_shadowed_refusals(&mut parsed.skipped, &seen);
    let skipped_total =
        parsed.skipped.unparsable + parsed.skipped.bad_field + parsed.skipped.duplicate + parsed.skipped.other_type + parsed.skipped.name_dropped;
    if skipped_total > 0 {
        tracing::warn!(skipped_total, "resources skipped");
    }
    Ok(parsed)
}


/// A privilege name is a Proxmox constant: ASCII letter first, then letters, digits, `.`, `_` or `-`.
pub fn valid_privilege(name: &str) -> bool {
    name.len() <= MAX_PRIVILEGE_LEN
        && name.chars().next().is_some_and(|first| first.is_ascii_alphabetic())
        && name.chars().all(|next| next.is_ascii_alphanumeric() || matches!(next, '.' | '_' | '-'))
}


pub fn privilege_of(name: String, flag: u64) -> Result<(String, u8), ParseError> {
    if valid_privilege(&name) && flag <= MAX_FLAG {
        Ok((name, u8::from(flag == MAX_FLAG)))
    } else {
        Err(ParseError::BadPermission)
    }
}


/// One ACL path: the privileges counted before built, within the per-path cap and the grant total.
pub fn convert_path(path: &str, raw: &RawValue, used: usize, limits: &Limits) -> Result<PathPrivileges, ParseError> {
    let count = count_entries(raw.get())?;
    if count > limits.max_privileges {
        Err(ParseError::TooManyPrivileges {
            count,
            max: limits.max_privileges,
        })?;
    }
    let total = used.saturating_add(count);
    if total > limits.max_grants {
        Err(ParseError::TooManyGrants {
            count: total,
            max: limits.max_grants,
        })?;
    }
    if !valid_acl_path(path) {
        Err(ParseError::BadPermission)?;
    }
    let mut map_reader = serde_json::Deserializer::from_str(raw.get());
    let granted: Vec<(String, u64)> = Map::<Same, Same>::deserialize_as(&mut map_reader).map_err(malformed)?;
    let privileges = granted
        .into_iter()
        .map(|(name, flag)| privilege_of(name, flag))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    Ok(PathPrivileges {
        path: path.to_owned(),
        privileges,
    })
}


/// Reads the `data` map of `GET /access/permissions` (path, then privilege, then flag); any refusal fails the whole answer, so a check never passes on a partial read.
pub fn parse_permissions<Source: Read>(reader: Source, limits: &Limits) -> Result<Permissions, ParseError> {
    let buffer = read_bounded(reader, limits)?;
    let root: RawData = serde_json::from_slice(&buffer).map_err(malformed)?;
    let count = count_entries(root.data.get())?;
    if count > limits.max_paths {
        Err(ParseError::TooManyItems {
            count,
            max: limits.max_paths,
        })?;
    }
    let mut map_reader = serde_json::Deserializer::from_str(root.data.get());
    let entries: Vec<(String, &RawValue)> = Map::<Same, Same>::deserialize_as(&mut map_reader).map_err(malformed)?;
    let (paths, _) = entries.iter().try_fold((Vec::new(), NO_GRANTS), |(mut paths, used), (path, raw)| {
        let entry = convert_path(path, raw, used, limits)?;
        let grants = used.saturating_add(entry.privileges.len());
        paths.push(entry);
        Ok::<_, ParseError>((paths, grants))
    })?;
    Ok(Permissions { paths })
}
