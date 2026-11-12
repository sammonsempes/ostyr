use crate::error::ParseError;
use crate::limits::{Limits, COLLECTION_SLACK};
use crate::model::{NodeItem, Parsed, PodItem, SkipReason, Skipped};
use crate::text::{valid_label_key, valid_label_value, valid_text};
use crate::types::{BorrowedLabels, LabelsAndExtra};
use serde::de::IgnoredAny;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_with::{DeserializeAs, Map, Same};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::net::IpAddr;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;


pub const POD_LIST_KIND: &str = "PodList";


pub const NODE_LIST_KIND: &str = "NodeList";


pub const OWNERS_KEPT: usize = 1;


pub const INTERNAL_IP: &str = "InternalIP";


#[derive(Deserialize)]
struct RawList<'a> {
    #[serde(borrow)]
    kind: Cow<'a, str>,
    #[serde(borrow)]
    items: &'a RawValue,
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
    #[serde(borrow)]
    labels: Option<&'a RawValue>,
    #[serde(borrow, rename = "ownerReferences")]
    owners: Option<&'a RawValue>,
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
    #[serde(borrow)]
    containers: Option<&'a RawValue>,
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
    #[serde(borrow)]
    addresses: Option<&'a RawValue>,
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


fn unparsable(_error: serde_json::Error) -> SkipReason {
    SkipReason::Unparsable
}


/// A JSON array counted without allocating (`IgnoredAny` is zero-sized), built only when its count is within `cap * COLLECTION_SLACK`.
pub fn bounded_seq<'a, Entry: Deserialize<'a>>(raw: Option<&'a RawValue>, cap: usize) -> Result<(Vec<Entry>, usize), SkipReason> {
    let text = raw.map_or("[]", |value| value.get());
    let count = serde_json::from_str::<Vec<IgnoredAny>>(text).map_err(unparsable)?.len();
    if count > cap.saturating_mul(COLLECTION_SLACK) {
        Err(SkipReason::BadField)
    } else {
        let mut entries = serde_json::from_str::<Vec<Entry>>(text).map_err(unparsable)?;
        entries.truncate(cap);
        let extra = count.saturating_sub(entries.len());
        Ok((entries, extra))
    }
}


/// A JSON object counted entry by entry without allocating, built only when its count is within `cap * COLLECTION_SLACK`.
pub fn bounded_labels(raw: Option<&RawValue>, cap: usize) -> Result<LabelsAndExtra<'_>, SkipReason> {
    let text = raw.map_or("{}", |value| value.get());
    let mut counter = serde_json::Deserializer::from_str(text);
    let entries: Vec<(IgnoredAny, IgnoredAny)> = Map::<Same, Same>::deserialize_as(&mut counter).map_err(unparsable)?;
    if entries.len() > cap.saturating_mul(COLLECTION_SLACK) {
        Err(SkipReason::BadField)
    } else {
        let labels = serde_json::from_str::<BorrowedLabels>(text).map_err(unparsable)?;
        let extra = labels.len().saturating_sub(cap);
        Ok((labels, extra))
    }
}


/// One pod element, parsed alone: required namespace, name and uid; labels and images are checked up to their caps and the rest counted.
pub fn convert_pod(raw: &RawValue, limits: &Limits) -> Result<PodItem, SkipReason> {
    let pod: RawPod = serde_json::from_str(raw.get()).map_err(unparsable)?;
    let metadata = &pod.metadata;
    let (containers, extra_containers) = bounded_seq::<RawContainer>(pod.spec.containers, limits.max_containers)?;
    let images = containers
        .iter()
        .map(|container| required_of(container.image.as_deref(), limits))
        .collect::<Result<Vec<_>, _>>()?;
    let (all_labels, extra_labels) = bounded_labels(metadata.labels, limits.max_labels)?;
    let labels = all_labels
        .iter()
        .take(limits.max_labels)
        .map(|(key, value)| label_of(key, value))
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let (owners, _) = bounded_seq::<RawOwner>(metadata.owners, OWNERS_KEPT)?;
    let owner = owners.first();
    Ok(PodItem {
        namespace: required_of(metadata.namespace.as_deref(), limits)?,
        name: required_of(metadata.name.as_deref(), limits)?,
        uid: required_of(metadata.uid.as_deref(), limits)?,
        node_name: text_of(pod.spec.node_name.as_deref(), limits)?,
        phase: text_of(pod.status.phase.as_deref(), limits)?,
        images,
        extra_containers,
        owner_kind: owner.map(|found| required_of(found.kind.as_deref(), limits)).transpose()?,
        owner_name: owner.map(|found| required_of(found.name.as_deref(), limits)).transpose()?,
        extra_labels,
        labels,
        created_unix: metadata.created.as_deref().map(unix_of).transpose()?,
    })
}


/// One node element, parsed alone: required name and uid, the InternalIP addresses up to the cap and the rest counted.
pub fn convert_node(raw: &RawValue, limits: &Limits) -> Result<NodeItem, SkipReason> {
    let node: RawNode = serde_json::from_str(raw.get()).map_err(unparsable)?;
    let (listed, extra_addresses) = bounded_seq::<RawAddress>(node.status.addresses, limits.max_addresses)?;
    let addresses = listed
        .iter()
        .filter(|address| address.kind.as_deref() == Some(INTERNAL_IP))
        .map(|address| ip_of(address.address.as_deref()))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(NodeItem {
        name: required_of(node.metadata.name.as_deref(), limits)?,
        uid: required_of(node.metadata.uid.as_deref(), limits)?,
        kubelet_version: text_of(node.status.node_info.kubelet_version.as_deref(), limits)?,
        os_image: text_of(node.status.node_info.os_image.as_deref(), limits)?,
        addresses,
        extra_addresses,
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
    let count = serde_json::from_str::<Vec<IgnoredAny>>(list.items.get()).map_err(malformed)?.len();
    if count > limits.max_items {
        Err(ParseError::TooManyItems {
            count,
            max: limits.max_items,
        })?;
    }
    let items = serde_json::from_str::<Vec<&RawValue>>(list.items.get()).map_err(malformed)?;
    let mut parsed = Parsed {
        items: Vec::new(),
        skipped: Skipped::default(),
    };
    let mut seen = HashSet::new();
    for raw in &items {
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
