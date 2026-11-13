use crate::error::StatsError;
use crate::model::{KeyReport, StackLimits};
use crate::stack::{group_by_key, summarise};
use crate::types::Observation;
use std::collections::BTreeSet;


/// Keys of `current` absent from the baseline, with their entities.
pub fn first_seen(baseline: &BTreeSet<String>, current: &[Observation], limits: &StackLimits) -> Result<KeyReport, StatsError> {
    let (groups, rows_dropped) = group_by_key(current, baseline, limits)?;
    Ok(KeyReport {
        keys: summarise(groups, usize::MAX, limits.max_examples),
        rows_dropped,
    })
}
