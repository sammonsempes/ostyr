//! KEV rematch without a rescan.

use crate::model::ScoredFinding;
use crate::priority::rank;
use std::collections::BTreeSet;


/// Findings whose record id or CVE alias is in `new_kev_ids` and not yet flagged, returned flagged and ranked.
pub fn kev_rematch(inventory: &[ScoredFinding], new_kev_ids: &BTreeSet<String>) -> Vec<ScoredFinding> {
    let affected = inventory
        .iter()
        .filter(|scored| !scored.kev)
        .filter(|scored| {
            new_kev_ids.contains(&scored.finding.record_id) || scored.finding.cve_aliases.iter().any(|alias| new_kev_ids.contains(alias))
        })
        .map(|scored| ScoredFinding { kev: true, ..scored.clone() })
        .collect();
    rank(affected)
}
