use crate::model::{Asset, RelationKind, Relationship};
use std::collections::BTreeSet;


pub const MAX_IMPACT_DEPTH: usize = 8;


pub const BUSINESS_SERVICE_ATTRIBUTE: &str = "business_service";


pub fn propagates(kind: RelationKind) -> bool {
    matches!(kind, RelationKind::DependsOn | RelationKind::RunsOn)
}


/// The asset and every asset that depends on it or runs on it, up to `MAX_IMPACT_DEPTH` edges; an iterative breadth-first walk, so cycles end.
pub fn impacted_assets(start: &str, relationships: &[Relationship]) -> BTreeSet<String> {
    let origin: BTreeSet<String> = BTreeSet::from([start.to_string()]);
    let (reached, _) = (0..MAX_IMPACT_DEPTH).fold((origin.clone(), origin), |(visited, frontier), _| {
        let next: BTreeSet<String> = relationships
            .iter()
            .filter(|edge| propagates(edge.kind) && frontier.contains(&edge.to) && !visited.contains(&edge.from))
            .map(|edge| edge.from.clone())
            .collect();
        (visited.union(&next).cloned().collect(), next)
    });
    reached
}


pub fn impacted_services(start: &str, assets: &[Asset], relationships: &[Relationship]) -> BTreeSet<String> {
    let reached = impacted_assets(start, relationships);
    assets
        .iter()
        .filter(|asset| reached.contains(&asset.id))
        .filter_map(|asset| asset.attributes.get(BUSINESS_SERVICE_ATTRIBUTE))
        .map(|attribute| attribute.value.clone())
        .collect()
}
