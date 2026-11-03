use crate::error::Problem;
use crate::model::{Catalogue, CatalogueEntry, ParamSpec, ParamType};
use std::sync::LazyLock;


pub const APPROVAL_ACTION: &str = "request_approval";


pub const APPROVAL_TARGET_PARAM: &str = "action";


fn required(kind: ParamType) -> ParamSpec {
    ParamSpec { kind, optional: false }
}


/// The built-in approval step: no connector, never destructive, never counted by the breakers.
pub static APPROVAL_ENTRY: LazyLock<CatalogueEntry> = LazyLock::new(|| CatalogueEntry {
    connector: None,
    action: APPROVAL_ACTION.to_owned(),
    params: [
        ("role", required(ParamType::String)),
        ("timeout", required(ParamType::Duration)),
        (APPROVAL_TARGET_PARAM, required(ParamType::String)),
    ]
    .into_iter()
    .map(|(name, spec)| (name.to_owned(), spec))
    .collect(),
    compensate: None,
    destructive: false,
    breaker: None,
});


pub fn find_entry<'a>(catalogue: &'a Catalogue, connector: Option<&str>, action: &str) -> Option<&'a CatalogueEntry> {
    if connector.is_none() && action == APPROVAL_ACTION {
        Some(&APPROVAL_ENTRY)
    } else {
        catalogue
            .actions
            .iter()
            .find(|entry| entry.connector.as_deref() == connector && entry.action == action)
    }
}


pub fn entry_label(entry: &CatalogueEntry) -> String {
    entry
        .connector
        .as_ref()
        .map_or_else(|| entry.action.clone(), |connector| format!("{connector}/{}", entry.action))
}


pub fn bad_entry(entry: &CatalogueEntry, reason: String) -> Problem {
    Problem::BadCatalogue {
        entry: entry_label(entry),
        reason,
    }
}


pub fn duplicate_problem(catalogue: &Catalogue, entry: &CatalogueEntry) -> Option<Problem> {
    let same = catalogue
        .actions
        .iter()
        .filter(|other| other.connector == entry.connector && other.action == entry.action)
        .count();
    (same > 1).then(|| bad_entry(entry, "declared more than once".to_owned()))
}


pub fn reserved_problem(entry: &CatalogueEntry) -> Option<Problem> {
    (entry.connector.is_none() && entry.action == APPROVAL_ACTION)
        .then(|| bad_entry(entry, "the name is reserved for the built-in approval".to_owned()))
}


pub fn compensate_problem(catalogue: &Catalogue, entry: &CatalogueEntry) -> Option<Problem> {
    entry
        .compensate
        .as_ref()
        .filter(|compensate| find_entry(catalogue, entry.connector.as_deref(), compensate).is_none())
        .map(|compensate| bad_entry(entry, format!("compensation `{compensate}` is not in the catalogue")))
}


pub fn binding_problems(entry: &CatalogueEntry) -> Vec<Problem> {
    entry
        .breaker
        .iter()
        .flat_map(|binding| {
            [Some(&binding.target), binding.duration.as_ref(), binding.machines.as_ref()]
                .into_iter()
                .flatten()
                .filter(|name| !entry.params.contains_key(*name))
                .map(|name| bad_entry(entry, format!("breaker binding names the unknown parameter `{name}`")))
                .collect::<Vec<_>>()
        })
        .collect()
}


pub fn catalogue_problems(catalogue: &Catalogue) -> Vec<Problem> {
    catalogue
        .actions
        .iter()
        .flat_map(|entry| {
            [
                duplicate_problem(catalogue, entry),
                reserved_problem(entry),
                compensate_problem(catalogue, entry),
            ]
            .into_iter()
            .flatten()
            .chain(binding_problems(entry))
            .collect::<Vec<_>>()
        })
        .collect()
}
