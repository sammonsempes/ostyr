use crate::model::{Refusal, Route};
use crate::validate::{prefix_key, SHADOWED};
use std::collections::{BTreeMap, BTreeSet};


pub const TOO_MANY_RENDERED: &str = "too many rendered routes";


/// The path keys of a route, the empty key standing for every path of its hosts.
pub fn route_keys(route: &Route) -> BTreeSet<&str> {
    let keys: BTreeSet<&str> = route.prefixes.iter().map(|prefix| prefix_key(prefix)).collect();
    if keys.is_empty() {
        BTreeSet::from([""])
    } else {
        keys
    }
}


/// The first route owning any (host, key) pair of `route`; when none does, the pairs are recorded for `index`.
pub fn claim(owners: &mut BTreeMap<(String, String), usize>, index: usize, route: &Route) -> Option<usize> {
    let keys = route_keys(route);
    let pairs: Vec<(String, String)> = route
        .hosts
        .iter()
        .flat_map(|host| keys.iter().map(move |key| (host.clone(), (*key).to_string())))
        .collect();
    let first = pairs.iter().filter_map(|pair| owners.get(pair).copied()).min();
    if first.is_none() {
        pairs.into_iter().for_each(|pair| {
            owners.insert(pair, index);
        });
    }
    first
}


/// Splits the accepted routes (file index, route) into the reachable ones and the shadowed ones.
pub fn place(accepted: Vec<(usize, Route)>) -> (Vec<(usize, Route)>, Vec<Refusal>) {
    let mut owners = BTreeMap::new();
    let mut kept = Vec::new();
    let mut shadowed = Vec::new();
    accepted.into_iter().for_each(|(index, route)| match claim(&mut owners, index, &route) {
        Some(owner) => shadowed.push(Refusal {
            index,
            reason: SHADOWED,
            shadowed_by: Some(owner),
        }),
        None => kept.push((index, route)),
    });
    (kept, shadowed)
}


/// Keeps routes in file order while their Caddy routes fit in `max`; the first that does not fit and every later one is refused.
pub fn cap_rendered(placed: Vec<(usize, Route)>, max: usize) -> (Vec<Route>, Vec<Refusal>) {
    let mut total = 0;
    let mut full = false;
    let mut kept = Vec::new();
    let mut refused = Vec::new();
    placed.into_iter().for_each(|(index, route)| {
        total += route_keys(&route).len();
        full = full || total > max;
        if full {
            refused.push(Refusal {
                index,
                reason: TOO_MANY_RENDERED,
                shadowed_by: None,
            });
        } else {
            kept.push(route);
        }
    });
    (kept, refused)
}
