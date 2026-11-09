//! Difference between two SBOMs of one artefact.

use crate::error::DiffError;
use crate::limits::NO_VERSION;
use crate::model::{Sbom, SbomDiff, VersionChange, VersionSet};
use crate::types::VersionsByKey;
use std::collections::{BTreeMap, BTreeSet};


/// Keyed by purl without version; one key can hold several versions (architectures), so the sets are compared.
pub fn diff(old: &Sbom, new: &Sbom) -> Result<SbomDiff, DiffError> {
    (old.tenant == new.tenant).then_some(()).ok_or(DiffError::TenantMismatch)?;
    (old.artefact == new.artefact).then_some(()).ok_or(DiffError::ArtefactMismatch)?;
    let before = versions_by_key(old);
    let after = versions_by_key(new);
    Ok(SbomDiff {
        added: only_in(&after, &before),
        removed: only_in(&before, &after),
        changed: before
            .iter()
            .filter_map(|(key, old_versions)| {
                after
                    .get(key)
                    .filter(|new_versions| *new_versions != old_versions)
                    .map(|new_versions| VersionChange {
                        key: key.to_string(),
                        old_versions: owned(old_versions),
                        new_versions: owned(new_versions),
                    })
            })
            .collect(),
    })
}


fn versions_by_key(sbom: &Sbom) -> VersionsByKey<'_> {
    sbom.components.iter().fold(BTreeMap::new(), |mut grouped, component| {
        grouped
            .entry(component.key.as_str())
            .or_insert_with(BTreeSet::new)
            .insert(component.version.as_deref().unwrap_or(NO_VERSION));
        grouped
    })
}


fn only_in(side: &VersionsByKey, other: &VersionsByKey) -> Vec<VersionSet> {
    side.iter()
        .filter(|(key, _)| !other.contains_key(*key))
        .map(|(key, versions)| VersionSet {
            key: key.to_string(),
            versions: owned(versions),
        })
        .collect()
}


fn owned(versions: &BTreeSet<&str>) -> Vec<String> {
    versions.iter().map(|version| version.to_string()).collect()
}
