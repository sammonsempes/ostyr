//! Fills EPSS and KEV on scored findings from the public catalogues.

use crate::epss::EpssScores;
use crate::kev::KevCatalogue;
use crate::model::{Finding, ScoredFinding};
use crate::text::is_cve_id;


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


/// Keeps at most `max` valid CVE aliases, the catalogue's ids first then ascending; every alias left out, invalid ones included, is counted.
pub fn cap_aliases(scored: ScoredFinding, kev: &KevCatalogue, max: usize) -> ScoredFinding {
    cap_aliases_counted(scored, kev, max).0
}


/// `cap_aliases` and how many catalogue ids the cap left out (the KEV ids are kept first, so this is above 0 only past `max` of them).
pub fn cap_aliases_counted(scored: ScoredFinding, kev: &KevCatalogue, max: usize) -> (ScoredFinding, u64) {
    let total = scored.finding.cve_aliases.len();
    let mut valid: Vec<String> = scored.finding.cve_aliases.iter().filter(|alias| is_cve_id(alias)).cloned().collect();
    valid.sort_by_key(|alias| (!kev.ids.contains(alias), alias.clone()));
    let kev_total = valid.iter().filter(|alias| kev.ids.contains(*alias)).count();
    valid.truncate(max);
    let kev_kept = valid.iter().filter(|alias| kev.ids.contains(*alias)).count();
    let omitted = (total - valid.len()) as u64;
    let capped = ScoredFinding {
        finding: Finding {
            cve_aliases: valid,
            aliases_omitted: scored.finding.aliases_omitted.saturating_add(omitted),
            ..scored.finding
        },
        ..scored
    };
    (capped, (kev_total - kev_kept) as u64)
}
