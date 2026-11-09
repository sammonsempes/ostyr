use crate::model::{DropReason, Limits};
use crate::types::{Labels, SeriesKey};
use std::collections::{BTreeMap, BTreeSet};


#[derive(Debug, Default)]
pub struct TenantCardinality {
    pub series: BTreeSet<SeriesKey>,
    pub values: BTreeMap<String, BTreeSet<String>>,
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


pub fn admit_series(state: &mut CardinalityState, tenant: &str, name: &str, labels: &Labels, limits: &Limits) -> Result<(), DropReason> {
    let entry = state.tenants.entry(tenant.to_string()).or_default();
    let key = (name.to_string(), labels.clone());
    if entry.series.contains(&key) {
        Ok(())
    } else if entry.series.len() >= limits.max_series_per_tenant {
        Err(DropReason::SeriesCap)
    } else if labels.iter().any(|(label, value)| value_cap_hit(entry, label, value, limits)) {
        Err(DropReason::LabelValueCap)
    } else {
        labels.iter().for_each(|(label, value)| {
            entry.values.entry(label.clone()).or_default().insert(value.clone());
        });
        entry.series.insert(key);
        Ok(())
    }
}
