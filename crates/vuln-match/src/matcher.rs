//! Inventory against OSV records.

use crate::error::VersionError;
use crate::model::{
    Affected, Event, EventKind, Family, Finding, MatchReport, OsvRecord, Package, ParsedEvent, ParsedVersion, Range, Unmatched, UnmatchedReason,
    Verdict,
};
use crate::version::{ecosystem_base, family_of, parse_version};
use std::cmp::Ordering;
use std::collections::BTreeSet;


const RANGE_KINDS: [&str; 2] = ["ECOSYSTEM", "SEMVER"];


const CVE_PREFIX: &str = "CVE-";


const ZERO_VERSION: &str = "0";


enum Outcome {
    Found(Finding),
    Missed(Unmatched),
}


/// Findings and unmatched entries are sorted, so equal input gives equal output.
pub fn match_inventory(packages: &[Package], records: &[OsvRecord]) -> MatchReport {
    let outcomes: Vec<Outcome> = packages.iter().flat_map(|package| match_package(package, records)).collect();
    let mut findings: Vec<Finding> = outcomes
        .iter()
        .filter_map(|outcome| match outcome {
            Outcome::Found(finding) => Some(finding.clone()),
            Outcome::Missed(_) => None,
        })
        .collect();
    let mut unmatched: Vec<Unmatched> = outcomes
        .into_iter()
        .filter_map(|outcome| match outcome {
            Outcome::Found(_) => None,
            Outcome::Missed(entry) => Some(entry),
        })
        .collect();
    findings.sort();
    findings.dedup();
    unmatched.sort();
    unmatched.dedup();
    let mut report = MatchReport {
        findings,
        unmatched,
        ..MatchReport::default()
    };
    report
        .unmatched
        .iter()
        .for_each(|entry| *report.unmatched_counts.entry(entry.reason).or_insert(0) += 1);
    if !report.unmatched.is_empty() {
        tracing::warn!(count = report.unmatched.len(), "packages or records left unmatched");
    }
    report
}


fn match_package(package: &Package, records: &[OsvRecord]) -> Vec<Outcome> {
    match prepare(package) {
        Err(error) => {
            tracing::debug!(%error, package = %package.name, "package cannot be matched");
            vec![Outcome::Missed(unmatched(package, None, reason_of(&error)))]
        }
        Ok((family, installed)) => records
            .iter()
            .filter_map(|record| evaluate(record, package, family, &installed))
            .collect(),
    }
}


fn prepare(package: &Package) -> Result<(Family, ParsedVersion), VersionError> {
    let family = family_of(&package.ecosystem)?;
    let installed = parse_version(family, &package.version)?;
    Ok((family, installed))
}


fn reason_of(error: &VersionError) -> UnmatchedReason {
    match error {
        VersionError::UnknownEcosystem(_) => UnmatchedReason::UnknownEcosystem,
        VersionError::Unparsable { .. } => UnmatchedReason::UnparsableVersion,
    }
}


fn unmatched(package: &Package, record_id: Option<&str>, reason: UnmatchedReason) -> Unmatched {
    Unmatched {
        package: package.clone(),
        record_id: record_id.map(str::to_string),
        reason,
    }
}


fn evaluate(record: &OsvRecord, package: &Package, family: Family, installed: &ParsedVersion) -> Option<Outcome> {
    match record_verdict(record, package, family, installed) {
        Ok(Verdict::Affected { fixed }) => Some(Outcome::Found(finding(record, package, fixed))),
        Ok(Verdict::NotAffected) => None,
        Err(error) => {
            tracing::debug!(%error, record = %record.id, package = %package.name, "record version cannot be compared");
            Some(Outcome::Missed(unmatched(
                package,
                Some(&record.id),
                UnmatchedReason::UnparsableRecordVersion,
            )))
        }
    }
}


fn finding(record: &OsvRecord, package: &Package, fixed: Option<String>) -> Finding {
    let cve_aliases: BTreeSet<String> = std::iter::once(&record.id)
        .chain(&record.aliases)
        .filter(|name| name.starts_with(CVE_PREFIX))
        .cloned()
        .collect();
    Finding {
        package: package.name.clone(),
        installed_version: package.version.clone(),
        ecosystem: package.ecosystem.clone(),
        record_id: record.id.clone(),
        cve_aliases: cve_aliases.into_iter().collect(),
        fixed_version: fixed,
    }
}


fn record_verdict(record: &OsvRecord, package: &Package, family: Family, installed: &ParsedVersion) -> Result<Verdict, VersionError> {
    record
        .affected
        .iter()
        .filter(|affected| applies_to(affected, package))
        .try_fold(Verdict::NotAffected, |verdict, affected| match verdict {
            Verdict::Affected { .. } => Ok(verdict),
            Verdict::NotAffected => affected_verdict(affected, family, installed),
        })
}


fn applies_to(affected: &Affected, package: &Package) -> bool {
    let record_ecosystem = affected.package.ecosystem.as_str();
    affected.package.name == package.name
        && ecosystem_base(record_ecosystem) == ecosystem_base(&package.ecosystem)
        && (!record_ecosystem.contains(':') || record_ecosystem == package.ecosystem)
}


fn affected_verdict(affected: &Affected, family: Family, installed: &ParsedVersion) -> Result<Verdict, VersionError> {
    let listed = affected.versions.iter().try_fold(false, |found, text| {
        let version = parse_version(family, text)?;
        Ok::<bool, VersionError>(found || version.cmp(installed) == Ordering::Equal)
    })?;
    if listed {
        Ok(Verdict::Affected { fixed: None })
    } else {
        affected
            .ranges
            .iter()
            .filter(|range| RANGE_KINDS.contains(&range.kind.as_str()))
            .try_fold(Verdict::NotAffected, |verdict, range| match verdict {
                Verdict::Affected { .. } => Ok(verdict),
                Verdict::NotAffected => range_verdict(range, family, installed),
            })
    }
}


fn range_verdict(range: &Range, family: Family, installed: &ParsedVersion) -> Result<Verdict, VersionError> {
    let mut events: Vec<ParsedEvent> = range
        .events
        .iter()
        .map(|event| parse_event(event, family))
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect();
    events.sort_by(|left, right| left.version.cmp(&right.version));
    let current = Some(installed);
    let vulnerable = events.iter().fold(false, |state, event| match event.kind {
        EventKind::Introduced => state || event.version.as_ref() <= current,
        EventKind::Fixed => state && current < event.version.as_ref(),
        EventKind::LastAffected => state && current <= event.version.as_ref(),
    });
    let fixed = events
        .iter()
        .find(|event| event.kind == EventKind::Fixed && current < event.version.as_ref())
        .map(|event| event.text.clone());
    Ok(if vulnerable { Verdict::Affected { fixed } } else { Verdict::NotAffected })
}


fn parse_event(event: &Event, family: Family) -> Result<Option<ParsedEvent>, VersionError> {
    let typed = match event {
        Event::Introduced(text) => Some((EventKind::Introduced, text)),
        Event::Fixed(text) => Some((EventKind::Fixed, text)),
        Event::LastAffected(text) => Some((EventKind::LastAffected, text)),
        Event::Limit(_) => None,
    };
    typed
        .map(|(kind, text)| {
            let version = if kind == EventKind::Introduced && text == ZERO_VERSION {
                None
            } else {
                Some(parse_version(family, text)?)
            };
            Ok(ParsedEvent {
                kind,
                text: text.clone(),
                version,
            })
        })
        .transpose()
}
