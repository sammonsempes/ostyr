use crate::error::ParseError;
use crate::limits::Limits;
use crate::model::{NodeItem, Parsed, PodItem, SkipReason, Skipped};
use crate::text::{valid_label_key, valid_label_value, valid_text};
use serde::Deserialize;
use serde_json::value::RawValue;
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


pub const POD_LIST_KIND: &str = "PodList";


pub const NODE_LIST_KIND: &str = "NodeList";


pub const INTERNAL_IP: &str = "InternalIP";


#[derive(Deserialize)]
struct RawList<'a> {
    #[serde(borrow)]
    kind: Cow<'a, str>,
    #[serde(borrow)]
    items: Vec<&'a RawValue>,
}


#[derive(Deserialize, Default)]
struct RawOwner<'a> {
    #[serde(borrow)]
    kind: Option<Cow<'a, str>>,
    #[serde(borrow)]
    name: Option<Cow<'a, str>>,
}


#[derive(Deserialize, Default)]
struct RawMetadata<'a> {
    #[serde(borrow)]
    name: Option<Cow<'a, str>>,
    #[serde(borrow)]
    namespace: Option<Cow<'a, str>>,
    #[serde(borrow)]
    uid: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "creationTimestamp")]
    created: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    labels: BTreeMap<Cow<'a, str>, Cow<'a, str>>,
    #[serde(borrow, default, rename = "ownerReferences")]
    owners: Vec<RawOwner<'a>>,
}


#[derive(Deserialize, Default)]
struct RawContainer<'a> {
    #[serde(borrow)]
    image: Option<Cow<'a, str>>,
}


#[derive(Deserialize, Default)]
struct RawPodSpec<'a> {
    #[serde(borrow, rename = "nodeName")]
    node_name: Option<Cow<'a, str>>,
    #[serde(borrow, default)]
    containers: Vec<RawContainer<'a>>,
}


#[derive(Deserialize, Default)]
struct RawPodStatus<'a> {
    #[serde(borrow)]
    phase: Option<Cow<'a, str>>,
}


#[derive(Deserialize)]
struct RawPod<'a> {
    #[serde(borrow, default)]
    metadata: RawMetadata<'a>,
    #[serde(borrow, default)]
    spec: RawPodSpec<'a>,
    #[serde(borrow, default)]
    status: RawPodStatus<'a>,
}


#[derive(Deserialize, Default)]
struct RawNodeInfo<'a> {
    #[serde(borrow, rename = "kubeletVersion")]
    kubelet_version: Option<Cow<'a, str>>,
    #[serde(borrow, rename = "osImage")]
    os_image: Option<Cow<'a, str>>,
}


#[derive(Deserialize, Default)]
struct RawAddress<'a> {
    #[serde(borrow, rename = "type")]
    kind: Option<Cow<'a, str>>,
    #[serde(borrow)]
    address: Option<Cow<'a, str>>,
}


#[derive(Deserialize, Default)]
struct RawNodeStatus<'a> {
    #[serde(borrow, default, rename = "nodeInfo")]
    node_info: RawNodeInfo<'a>,
    #[serde(borrow, default)]
    addresses: Vec<RawAddress<'a>>,
}


#[derive(Deserialize)]
struct RawNode<'a> {
    #[serde(borrow, default)]
    metadata: RawMetadata<'a>,
    #[serde(borrow, default)]
    status: RawNodeStatus<'a>,
}


fn text_of(value: Option<&str>, limits: &Limits) -> Result<Option<String>, SkipReason> {
    value
        .map(|text| {
            if valid_text(text, limits.max_text_bytes) {
                Ok(text.to_owned())
            } else {
                Err(SkipReason::BadField)
            }
        })
        .transpose()
}


fn required_of(value: Option<&str>, limits: &Limits) -> Result<String, SkipReason> {
    text_of(value, limits)?.ok_or(SkipReason::BadField)
}


fn label_of(key: &str, value: &str) -> Result<(String, String), SkipReason> {
    if valid_label_key(key) && valid_label_value(value) {
        Ok((key.to_owned(), value.to_owned()))
    } else {
        Err(SkipReason::BadField)
    }
}


fn unix_of(text: &str) -> Result<i64, SkipReason> {
    OffsetDateTime::parse(text, &Rfc3339)
        .map(|moment| moment.unix_timestamp())
        .map_err(|_| SkipReason::BadField)
}


fn ip_of(value: Option<&str>) -> Result<IpAddr, SkipReason> {
    value.ok_or(SkipReason::BadField)?.parse::<IpAddr>().map_err(|_| SkipReason::BadField)
}


/// One pod element, parsed alone: required namespace, name and uid; labels and images are checked up to their caps and the rest counted.
pub fn convert_pod(raw: &RawValue, limits: &Limits) -> Result<PodItem, SkipReason> {
    let pod: RawPod = serde_json::from_str(raw.get()).map_err(|_| SkipReason::Unparsable)?;
    let metadata = &pod.metadata;
    let images = pod
        .spec
        .containers
        .iter()
        .take(limits.max_containers)
        .map(|container| required_of(container.image.as_deref(), limits))
        .collect::<Result<Vec<_>, _>>()?;
    let labels = metadata
        .labels
        .iter()
        .take(limits.max_labels)
        .map(|(key, value)| label_of(key, value))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let owner = metadata.owners.first();
    Ok(PodItem {
        namespace: required_of(metadata.namespace.as_deref(), limits)?,
        name: required_of(metadata.name.as_deref(), limits)?,
        uid: required_of(metadata.uid.as_deref(), limits)?,
        node_name: text_of(pod.spec.node_name.as_deref(), limits)?,
        phase: text_of(pod.status.phase.as_deref(), limits)?,
        images,
        extra_containers: pod.spec.containers.len().saturating_sub(limits.max_containers),
        owner_kind: owner.map(|found| required_of(found.kind.as_deref(), limits)).transpose()?,
        owner_name: owner.map(|found| required_of(found.name.as_deref(), limits)).transpose()?,
        extra_labels: metadata.labels.len().saturating_sub(limits.max_labels),
        labels,
        created_unix: metadata.created.as_deref().map(unix_of).transpose()?,
    })
}


/// One node element, parsed alone: required name and uid, the InternalIP addresses up to the cap and the rest counted.
pub fn convert_node(raw: &RawValue, limits: &Limits) -> Result<NodeItem, SkipReason> {
    let node: RawNode = serde_json::from_str(raw.get()).map_err(|_| SkipReason::Unparsable)?;
    let internal = node
        .status
        .addresses
        .iter()
        .filter(|address| address.kind.as_deref() == Some(INTERNAL_IP))
        .collect::<Vec<_>>();
    let addresses = internal
        .iter()
        .take(limits.max_addresses)
        .map(|address| ip_of(address.address.as_deref()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NodeItem {
        name: required_of(node.metadata.name.as_deref(), limits)?,
        uid: required_of(node.metadata.uid.as_deref(), limits)?,
        kubelet_version: text_of(node.status.node_info.kubelet_version.as_deref(), limits)?,
        os_image: text_of(node.status.node_info.os_image.as_deref(), limits)?,
        addresses,
        extra_addresses: internal.len().saturating_sub(limits.max_addresses),
    })
}


pub fn pod_uid(pod: &PodItem) -> &str {
    &pod.uid
}


pub fn node_uid(node: &NodeItem) -> &str {
    &node.uid
}


pub fn count_skip(skipped: &mut Skipped, reason: SkipReason) {
    match reason {
        SkipReason::Unparsable => skipped.unparsable += 1,
        SkipReason::BadField => skipped.bad_field += 1,
        SkipReason::Duplicate => skipped.duplicate += 1,
    }
}


fn malformed(error: serde_json::Error) -> ParseError {
    ParseError::Malformed {
        category: error.classify(),
        line: error.line(),
        column: error.column(),
    }
}


/// Reads at most `max_bytes`, checks kind and item count on the raw list, then parses each element alone; a duplicate uid is skipped.
pub fn parse_list<Source: Read, Item>(
    reader: Source,
    limits: &Limits,
    kind: &'static str,
    convert: fn(&RawValue, &Limits) -> Result<Item, SkipReason>,
    uid_of: fn(&Item) -> &str,
) -> Result<Parsed<Item>, ParseError> {
    let mut buffer = Vec::new();
    let mut limited = reader.take(limits.max_bytes.saturating_add(1));
    limited.read_to_end(&mut buffer).map_err(ParseError::Read)?;
    if limited.limit() == 0 {
        Err(ParseError::TooLarge { max: limits.max_bytes })?;
    }
    let list: RawList = serde_json::from_slice(&buffer).map_err(malformed)?;
    if list.kind != kind {
        Err(ParseError::WrongKind { expected: kind })?;
    }
    if list.items.len() > limits.max_items {
        Err(ParseError::TooManyItems {
            count: list.items.len(),
            max: limits.max_items,
        })?;
    }
    let mut parsed = Parsed {
        items: Vec::new(),
        skipped: Skipped::default(),
    };
    let mut seen = HashSet::new();
    for raw in &list.items {
        match convert(raw, limits) {
            Ok(item) if seen.insert(uid_of(&item).to_owned()) => parsed.items.push(item),
            Ok(_) => count_skip(&mut parsed.skipped, SkipReason::Duplicate),
            Err(reason) => count_skip(&mut parsed.skipped, reason),
        }
    }
    let skipped_total = parsed.skipped.unparsable + parsed.skipped.bad_field + parsed.skipped.duplicate;
    if skipped_total > 0 {
        tracing::warn!(kind, skipped_total, "elements skipped");
    }
    Ok(parsed)
}


pub fn parse_pods<Source: Read>(reader: Source, limits: &Limits) -> Result<Parsed<PodItem>, ParseError> {
    parse_list(reader, limits, POD_LIST_KIND, convert_pod, pod_uid)
}


pub fn parse_nodes<Source: Read>(reader: Source, limits: &Limits) -> Result<Parsed<NodeItem>, ParseError> {
    parse_list(reader, limits, NODE_LIST_KIND, convert_node, node_uid)
}
