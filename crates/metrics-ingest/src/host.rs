use crate::cardinality::CardinalityState;
use crate::decode::{admit_point, count_drop, resource_labels, Point, Series};
use crate::model::{DropReason, HostCaller, Limits, MetricKind, Outcome, Refusal, Spec};
use crate::types::{KeySet, RawField, ResourceLabels};
use opentelemetry_proto::tonic::common::v1::{any_value::Value as AnyKind, AnyValue, KeyValue};
use serde::de::IgnoredAny;
use serde::{Deserialize, Deserializer};
use serde_json::value::RawValue;
use std::collections::BTreeMap;


pub const MAX_HOST_EVENT_BYTES: usize = 262_144;


pub const MAX_MOUNTS: usize = 64;


pub const MAX_RATIO: f64 = 1.0;


pub const HOST_DATASET: &str = "ostyr.host_metrics";


pub const HOST_LABEL: &str = "host.id";


pub const TIMESTAMP_KEY: &str = "@timestamp";


pub const HOST_PREFIX: &str = "host.";


pub const FLAT_BOOT_ID: &str = "host.boot_id";


pub const NESTED_BOOT_ID: &str = "boot_id";


pub const MOUNT_LABEL: &str = "mountpoint";


pub const UNIT_RATIO: &str = "1";


pub const UNIT_BYTES: &str = "By";


pub const UNIT_SECONDS: &str = "s";


pub const UNIT_THREADS: &str = "{thread}";


pub const UNIT_PROCESSES: &str = "{process}";


pub const UNIT_MOUNTS: &str = "{mount}";


pub const CPU_UTILIZATION: Spec = Spec {
    name: "system.cpu.utilization",
    unit: UNIT_RATIO,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: true,
};


pub const MEMORY_LIMIT: Spec = Spec {
    name: "system.memory.limit",
    unit: UNIT_BYTES,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const MEMORY_AVAILABLE: Spec = Spec {
    name: "system.memory.available",
    unit: UNIT_BYTES,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const PAGING_LIMIT: Spec = Spec {
    name: "system.paging.limit",
    unit: UNIT_BYTES,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const PAGING_FREE: Spec = Spec {
    name: "system.paging.free",
    unit: UNIT_BYTES,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const LOAD_1M: Spec = Spec {
    name: "system.cpu.load_average.1m",
    unit: UNIT_THREADS,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const LOAD_5M: Spec = Spec {
    name: "system.cpu.load_average.5m",
    unit: UNIT_THREADS,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const LOAD_15M: Spec = Spec {
    name: "system.cpu.load_average.15m",
    unit: UNIT_THREADS,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const OOM_KILLS: Spec = Spec {
    name: "system.oom_kills",
    unit: UNIT_PROCESSES,
    kind: MetricKind::Counter,
    monotonic: true,
    ratio: false,
};


pub const UPTIME: Spec = Spec {
    name: "system.uptime",
    unit: UNIT_SECONDS,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const FILESYSTEM_LIMIT: Spec = Spec {
    name: "system.filesystem.limit",
    unit: UNIT_BYTES,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const FILESYSTEM_FREE: Spec = Spec {
    name: "system.filesystem.free",
    unit: UNIT_BYTES,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const METRICS_OMITTED: Spec = Spec {
    name: "ostyr.agent.metrics_omitted",
    unit: UNIT_MOUNTS,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const METRICS_FAILED: Spec = Spec {
    name: "ostyr.agent.metrics_failed",
    unit: UNIT_MOUNTS,
    kind: MetricKind::Gauge,
    monotonic: false,
    ratio: false,
};


pub const KNOWN_METRICS: &[&str] = &[
    CPU_UTILIZATION.name,
    MEMORY_LIMIT.name,
    MEMORY_AVAILABLE.name,
    PAGING_LIMIT.name,
    PAGING_FREE.name,
    LOAD_1M.name,
    LOAD_5M.name,
    LOAD_15M.name,
    OOM_KILLS.name,
    UPTIME.name,
    FILESYSTEM_LIMIT.name,
    FILESYSTEM_FREE.name,
];


/// A present key is always `Some`, a `null` included, so it is counted as not a number instead of read as absent.
pub fn present<'de, Source: Deserializer<'de>>(deserializer: Source) -> Result<RawField, Source::Error> {
    Box::<RawValue>::deserialize(deserializer).map(Some)
}


#[derive(Deserialize)]
pub struct EventPart {
    pub dataset: Option<String>,
}


#[derive(Default, Deserialize)]
pub struct MetricsPart {
    #[serde(rename = "system.cpu.utilization", default, deserialize_with = "present")]
    pub cpu_utilization: RawField,
    #[serde(rename = "system.memory.limit", default, deserialize_with = "present")]
    pub memory_limit: RawField,
    #[serde(rename = "system.memory.available", default, deserialize_with = "present")]
    pub memory_available: RawField,
    #[serde(rename = "system.paging.limit", default, deserialize_with = "present")]
    pub paging_limit: RawField,
    #[serde(rename = "system.paging.free", default, deserialize_with = "present")]
    pub paging_free: RawField,
    #[serde(rename = "system.cpu.load_average.1m", default, deserialize_with = "present")]
    pub load_1m: RawField,
    #[serde(rename = "system.cpu.load_average.5m", default, deserialize_with = "present")]
    pub load_5m: RawField,
    #[serde(rename = "system.cpu.load_average.15m", default, deserialize_with = "present")]
    pub load_15m: RawField,
    #[serde(rename = "system.oom_kills", default, deserialize_with = "present")]
    pub oom_kills: RawField,
    #[serde(rename = "system.uptime", default, deserialize_with = "present")]
    pub uptime: RawField,
    #[serde(rename = "system.filesystem.limit", default, deserialize_with = "present")]
    pub filesystem_limit: RawField,
    #[serde(rename = "system.filesystem.free", default, deserialize_with = "present")]
    pub filesystem_free: RawField,
}


#[derive(Deserialize)]
pub struct HostEvent {
    pub event: Option<EventPart>,
    #[serde(default)]
    pub metrics: MetricsPart,
    #[serde(default, deserialize_with = "present")]
    pub metrics_omitted: RawField,
    #[serde(default, deserialize_with = "present")]
    pub metrics_failed: RawField,
}


/// The key names of the objects the payload could use to claim an identity or add a metric, read without building any value.
#[derive(Deserialize)]
pub struct Shape {
    pub host: Option<KeySet>,
    pub metrics: Option<KeySet>,
}


#[derive(Deserialize)]
pub struct Mount {
    pub mountpoint: Option<String>,
    #[serde(default, deserialize_with = "present")]
    pub value: RawField,
}


pub struct Stamp<'a> {
    pub nanos: u64,
    pub resource: &'a ResourceLabels,
}


/// Converts one `ostyr.host_metrics` event: `host.id`, the tenant and the time are the caller's (the channel identity and the receive time).
pub fn host_rows(event: &[u8], caller: &HostCaller, limits: &Limits, state: &mut CardinalityState) -> Outcome {
    let mut outcome = Outcome {
        tenant: caller.tenant.to_string(),
        rows: Vec::new(),
        dropped: BTreeMap::new(),
        refusal: None,
        row_bytes: 0,
    };
    match parse_event(event).and_then(|(parsed, keys)| identify(&parsed, caller.agent_id, limits).map(|resource| (parsed, keys, resource))) {
        Ok((parsed, keys, resource)) => {
            note_count(&mut outcome, DropReason::PayloadIdentityIgnored, ignored_identity(&keys));
            note_count(&mut outcome, DropReason::UnknownMetric, unknown_metrics(&keys));
            emit(
                &parsed,
                &Stamp {
                    nanos: caller.received_nanos,
                    resource: &resource,
                },
                limits,
                state,
                &mut outcome,
            );
        }
        Err(refusal) => outcome.refusal = Some(refusal),
    }
    outcome
}


/// A zero count is not recorded, so the report lists only what happened.
pub fn note_count(outcome: &mut Outcome, reason: DropReason, amount: usize) {
    if amount > 0 {
        count_drop(outcome, reason, amount);
    }
}


pub struct Keys {
    pub top: KeySet,
    pub shape: Shape,
}


pub fn parse_event(event: &[u8]) -> Result<(HostEvent, Keys), Refusal> {
    if event.len() > MAX_HOST_EVENT_BYTES {
        Err(Refusal::TooLarge { bytes: event.len() })
    } else {
        let parsed = serde_json::from_slice::<HostEvent>(event).map_err(|_| Refusal::BadEvent)?;
        let top = serde_json::from_slice::<KeySet>(event).map_err(|_| Refusal::BadEvent)?;
        let shape = serde_json::from_slice::<Shape>(event).map_err(|_| Refusal::BadEvent)?;
        Ok((parsed, Keys { top, shape }))
    }
}


pub fn identify(event: &HostEvent, agent_id: &str, limits: &Limits) -> Result<ResourceLabels, Refusal> {
    let dataset = event.event.as_ref().and_then(|part| part.dataset.as_deref());
    if dataset == Some(HOST_DATASET) {
        let resource = resource_labels(&[string_pair(HOST_LABEL, agent_id)], limits);
        if resource.is_err() {
            Err(Refusal::BadHost)
        } else {
            Ok(resource)
        }
    } else {
        Err(Refusal::NotHostMetrics)
    }
}


/// Payload keys that claim a time or a host identity: they never reach a row, only this count.
pub fn ignored_identity(keys: &Keys) -> usize {
    let flat = keys
        .top
        .keys()
        .filter(|key| key.as_str() == TIMESTAMP_KEY || (key.starts_with(HOST_PREFIX) && key.as_str() != FLAT_BOOT_ID))
        .count();
    let nested = keys
        .shape
        .host
        .iter()
        .flat_map(KeySet::keys)
        .filter(|key| key.as_str() != NESTED_BOOT_ID)
        .count();
    flat + nested
}


pub fn unknown_metrics(keys: &Keys) -> usize {
    keys.shape
        .metrics
        .iter()
        .flat_map(KeySet::keys)
        .filter(|key| !KNOWN_METRICS.contains(&key.as_str()))
        .count()
}


pub fn string_pair(key: &str, value: &str) -> KeyValue {
    KeyValue {
        key: key.to_string(),
        value: Some(AnyValue {
            value: Some(AnyKind::StringValue(value.to_string())),
        }),
        ..KeyValue::default()
    }
}


/// A finite, non-negative number (negative zero refused, never a string or null); a ratio is also at most 1.
pub fn row_value(raw: &RawValue, ratio: bool) -> Result<f64, DropReason> {
    let number = raw.get().parse::<f64>().map_err(|_| DropReason::NotANumber)?;
    if number.is_finite() && !number.is_sign_negative() && (!ratio || number <= MAX_RATIO) {
        Ok(number)
    } else {
        Err(DropReason::OutOfRange)
    }
}


pub fn emit(event: &HostEvent, stamp: &Stamp, limits: &Limits, state: &mut CardinalityState, outcome: &mut Outcome) {
    let metrics = &event.metrics;
    [
        (&CPU_UTILIZATION, &metrics.cpu_utilization),
        (&MEMORY_LIMIT, &metrics.memory_limit),
        (&MEMORY_AVAILABLE, &metrics.memory_available),
        (&PAGING_LIMIT, &metrics.paging_limit),
        (&PAGING_FREE, &metrics.paging_free),
        (&LOAD_1M, &metrics.load_1m),
        (&LOAD_5M, &metrics.load_5m),
        (&LOAD_15M, &metrics.load_15m),
        (&OOM_KILLS, &metrics.oom_kills),
        (&UPTIME, &metrics.uptime),
        (&METRICS_OMITTED, &event.metrics_omitted),
        (&METRICS_FAILED, &event.metrics_failed),
    ]
    .iter()
    .for_each(|(spec, field)| field.iter().for_each(|raw| scalar_row(spec, raw, stamp, limits, state, outcome)));
    [
        (&FILESYSTEM_LIMIT, &metrics.filesystem_limit),
        (&FILESYSTEM_FREE, &metrics.filesystem_free),
    ]
    .iter()
    .for_each(|(spec, field)| field.iter().for_each(|raw| mounts_rows(spec, raw, stamp, limits, state, outcome)));
}


pub fn scalar_row(spec: &Spec, raw: &RawValue, stamp: &Stamp, limits: &Limits, state: &mut CardinalityState, outcome: &mut Outcome) {
    match row_value(raw, spec.ratio) {
        Ok(value) => point_row(spec, value, &[], stamp, limits, state, outcome),
        Err(reason) => count_drop(outcome, reason, 1),
    }
}


pub fn point_row(
    spec: &Spec,
    value: f64,
    attributes: &[KeyValue],
    stamp: &Stamp,
    limits: &Limits,
    state: &mut CardinalityState,
    outcome: &mut Outcome,
) {
    let series = Series {
        name: spec.name,
        unit: spec.unit,
        kind: spec.kind,
        monotonic: spec.monotonic,
        resource: stamp.resource,
    };
    let point = Point {
        attributes,
        timestamp_nanos: stamp.nanos,
        value,
        buckets: Vec::new(),
    };
    admit_point(&series, point, limits, state, outcome);
}


/// The entries are counted without being built, so more than `MAX_MOUNTS` drops the whole array, named and counted once.
pub fn mount_entries(raw: &RawValue) -> Result<Vec<Box<RawValue>>, DropReason> {
    let count = serde_json::from_str::<Vec<IgnoredAny>>(raw.get())
        .map_err(|_| DropReason::MalformedMounts)?
        .len();
    if count > MAX_MOUNTS {
        Err(DropReason::TooManyMounts)
    } else {
        serde_json::from_str::<Vec<Box<RawValue>>>(raw.get()).map_err(|_| DropReason::MalformedMounts)
    }
}


pub fn mount_value(entry: &RawValue) -> Result<(String, f64), DropReason> {
    let mount = serde_json::from_str::<Mount>(entry.get()).map_err(|_| DropReason::MalformedMounts)?;
    let path = mount.mountpoint.filter(|text| !text.is_empty()).ok_or(DropReason::EmptyName)?;
    let raw = mount.value.ok_or(DropReason::MissingValue)?;
    row_value(&raw, false).map(|value| (path, value))
}


pub fn mounts_rows(spec: &Spec, raw: &RawValue, stamp: &Stamp, limits: &Limits, state: &mut CardinalityState, outcome: &mut Outcome) {
    match mount_entries(raw) {
        Ok(entries) => entries.iter().for_each(|entry| match mount_value(entry) {
            Ok((path, value)) => point_row(spec, value, &[string_pair(MOUNT_LABEL, &path)], stamp, limits, state, outcome),
            Err(reason) => count_drop(outcome, reason, 1),
        }),
        Err(reason) => count_drop(outcome, reason, 1),
    }
}
