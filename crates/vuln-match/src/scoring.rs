//! Fills EPSS and KEV on scored findings from the public catalogues.

use crate::epss::EpssScores;
use crate::kev::KevCatalogue;
use crate::model::ScoredFinding;


/// A finding whose record id or CVE alias is in a catalogue gets the highest EPSS found and the KEV flag; others are returned unchanged.
pub fn score_findings(findings: &[ScoredFinding], epss: &EpssScores, kev: &KevCatalogue) -> Vec<ScoredFinding> {
    findings
        .iter()
        .map(|scored| {
            let ids: Vec<&String> = std::iter::once(&scored.finding.record_id)
                .chain(scored.finding.cve_aliases.iter())
                .collect();
            let best_epss = ids.iter().filter_map(|id| epss.scores.get(*id)).copied().reduce(f64::max);
            ScoredFinding {
                epss: best_epss.unwrap_or(scored.epss),
                kev: scored.kev || ids.iter().any(|id| kev.ids.contains(*id)),
                ..scored.clone()
            }
        })
        .collect()
}
