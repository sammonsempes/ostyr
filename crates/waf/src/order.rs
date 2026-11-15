use crate::model::{Refusal, Route};
use crate::validate::{prefix_key, SHADOWED};
use std::collections::{BTreeMap, BTreeSet};


/// The path keys of a route, the empty key standing for every path of its hosts.
pub fn route_keys(route: &Route) -> BTreeSet<&str> {
    let keys: BTreeSet<&str> = route.prefixes.iter().map(|prefix| prefix_key(prefix)).collect();
    if keys.is_empty() {
        BTreeSet::from([""])
    } else {
        keys
    }
}


/// The route owning every (host, key) pair of `route`, or none when one pair is new; the new pairs are then recorded.
pub fn claim(owners: &mut BTreeMap<(String, String), usize>, index: usize, route: &Route) -> Option<usize> {
    let keys = route_keys(route);
    let pairs: Vec<(String, String)> = route
        .hosts
        .iter()
        .flat_map(|host| keys.iter().map(move |key| (host.clone(), (*key).to_string())))
        .collect();
    let found = pairs.iter().map(|pair| owners.get(pair).copied()).collect::<Option<Vec<usize>>>();
    if found.is_none() {
        pairs.into_iter().for_each(|pair| {
            owners.entry(pair).or_insert(index);
        });
    }
    found.and_then(|owned| owned.first().copied())
}


/// Splits the accepted routes (file index, route) into the reachable ones and the shadowed ones.
pub fn place(accepted: Vec<(usize, Route)>) -> (Vec<Route>, Vec<Refusal>) {
    let mut owners = BTreeMap::new();
    let mut kept = Vec::new();
    let mut shadowed = Vec::new();
    accepted.into_iter().for_each(|(index, route)| match claim(&mut owners, index, &route) {
        Some(owner) => shadowed.push(Refusal {
            index,
            reason: SHADOWED,
            shadowed_by: Some(owner),
        }),
        None => kept.push(route),
    });
    (kept, shadowed)
}
