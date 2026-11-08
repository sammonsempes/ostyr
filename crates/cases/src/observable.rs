use crate::model::{Case, Observable, ObservableKind};
use crate::types::ObservableKey;
use std::collections::BTreeSet;


#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AlreadySeen {
    pub case_id: String,
    pub shared: Vec<ObservableKey>,
}


/// Trimmed; lowercased for IPs, domains, hashes and emails; a domain loses its trailing dot. URLs, file names and others keep their case.
pub fn normalise_value(kind: ObservableKind, value: &str) -> String {
    let trimmed = value.trim();
    match kind {
        ObservableKind::Domain => trimmed.trim_end_matches('.').to_lowercase(),
        ObservableKind::Ip | ObservableKind::Hash | ObservableKind::Email => trimmed.to_lowercase(),
        ObservableKind::Url | ObservableKind::Filename | ObservableKind::Other => trimmed.to_string(),
    }
}


pub fn key_of(observable: &Observable) -> ObservableKey {
    (observable.kind, normalise_value(observable.kind, &observable.value))
}


pub fn shared_keys(other: &Case, wanted: &BTreeSet<ObservableKey>) -> BTreeSet<ObservableKey> {
    other.observables.iter().map(key_of).filter(|key| wanted.contains(key)).collect()
}


/// The other cases of the same tenant that hold an observable of `case`, with the shared ones; another tenant's case is never returned.
pub fn already_seen(case: &Case, others: &[Case]) -> Vec<AlreadySeen> {
    let wanted: BTreeSet<ObservableKey> = case.observables.iter().map(key_of).collect();
    others
        .iter()
        .filter(|other| other.tenant == case.tenant && other.id != case.id)
        .map(|other| AlreadySeen {
            case_id: other.id.clone(),
            shared: shared_keys(other, &wanted).into_iter().collect(),
        })
        .filter(|seen| !seen.shared.is_empty())
        .collect()
}
