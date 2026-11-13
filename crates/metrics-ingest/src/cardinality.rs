use crate::model::{DropReason, Limits};
use crate::types::{Labels, SeriesKey};
use std::collections::{BTreeMap, BTreeSet};


pub const ENTRY_OVERHEAD_BYTES: usize = 64;


#[derive(Debug, Default)]
pub struct TenantCardinality {
    pub series: BTreeSet<SeriesKey>,
    pub values: BTreeMap<String, BTreeSet<String>>,
    pub bytes: usize,
}


#[derive(Debug, Default)]
pub struct CardinalityState {
    pub tenants: BTreeMap<String, TenantCardinality>,
}


pub fn value_cap_hit(tenant: &TenantCardinality, key: &str, value: &str, limits: &Limits) -> bool {
    let known = tenant.values.get(key);
    let present = known.is_some_and(|values| values.contains(value));
    let count = known.map_or(0, BTreeSet::len);
    !present && count >= limits.max_values_per_label
}


pub fn new_key_count(tenant: &TenantCardinality, labels: &Labels) -> usize {
    labels.iter().filter(|(label, _)| !tenant.values.contains_key(label)).count()
}


pub fn text_cost(text: &str) -> usize {
    text.len().saturating_add(ENTRY_OVERHEAD_BYTES)
}


/// Bytes the series would add: its own key plus every label key and value not stored yet.
pub fn series_cost(tenant: &TenantCardinality, key: &SeriesKey) -> usize {
    let (name, labels) = key;
    let own = labels
        .iter()
        .map(|(label, value)| text_cost(label).saturating_add(text_cost(value)))
        .fold(text_cost(name), usize::saturating_add);
    let fresh = labels
        .iter()
        .map(|(label, value)| {
            let known = tenant.values.get(label);
            let key_cost = if known.is_some() { 0 } else { text_cost(label) };
            let value_cost = if known.is_some_and(|values| values.contains(value)) {
                0
            } else {
                text_cost(value)
            };
            key_cost.saturating_add(value_cost)
        })
        .fold(0, usize::saturating_add);
    own.saturating_add(fresh)
}


/// Bytes admitting `(name, labels)` would add to the tenant's state: 0 for a known series, else `series_cost`.
pub fn new_series_cost(state: &CardinalityState, tenant: &str, name: &str, labels: &Labels) -> usize {
    let key = (name.to_string(), labels.clone());
    match state.tenants.get(tenant) {
        Some(entry) if entry.series.contains(&key) => 0,
        Some(entry) => series_cost(entry, &key),
        None => series_cost(&TenantCardinality::default(), &key),
    }
}


pub fn admit_series(state: &mut CardinalityState, tenant: &str, name: &str, labels: &Labels, limits: &Limits) -> Result<(), DropReason> {
    let entry = state.tenants.entry(tenant.to_string()).or_default();
    let key = (name.to_string(), labels.clone());
    let cost = series_cost(entry, &key);
    if entry.series.contains(&key) {
        Ok(())
    } else if entry.series.len() >= limits.max_series_per_tenant {
        Err(DropReason::SeriesCap)
    } else if entry.values.len().saturating_add(new_key_count(entry, labels)) > limits.max_label_keys_per_tenant {
        Err(DropReason::LabelKeyCap)
    } else if labels.iter().any(|(label, value)| value_cap_hit(entry, label, value, limits)) {
        Err(DropReason::LabelValueCap)
    } else if entry.bytes.saturating_add(cost) > limits.max_state_bytes_per_tenant {
        Err(DropReason::StateBytesCap)
    } else {
        labels.iter().for_each(|(label, value)| {
            entry.values.entry(label.clone()).or_default().insert(value.clone());
        });
        entry.series.insert(key);
        entry.bytes = entry.bytes.saturating_add(cost);
        Ok(())
    }
}
