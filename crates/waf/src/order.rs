use crate::caddy::CaddyRoute;
use crate::error::WafError;
use crate::limits::{CATCH_ALL_UPSTREAMS, ROUTE_INDENT_BYTES, ROUTE_SEPARATOR_BYTES};
use crate::model::{Budget, Refusal, Route};
use crate::render::{caddy_config, caddy_route};
use crate::validate::{prefix_key, SHADOWED};
use std::collections::{BTreeMap, BTreeSet};


pub const TOO_MANY_RENDERED: &str = "too many rendered routes";


pub const TOO_MANY_BYTES: &str = "too many rendered bytes";


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


/// The upstream handlers a route adds: each Caddy route runs one health checker per backend.
pub fn route_upstreams(route: &Route) -> usize {
    route_keys(route).len() * route.backends.len()
}


/// The bytes of one Caddy route inside the pretty document: its own lines indented by `ROUTE_INDENT_BYTES`, plus the comma and the line break.
pub fn caddy_route_bytes(route: &CaddyRoute) -> Result<usize, WafError> {
    let encoded = serde_json::to_vec_pretty(route)?;
    let lines = encoded.iter().filter(|byte| **byte == b'\n').count() + 1;
    Ok(encoded.len() + lines * ROUTE_INDENT_BYTES + ROUTE_SEPARATOR_BYTES)
}


/// The bytes a route adds to the document, one Caddy route per path key.
pub fn route_bytes(route: &Route) -> Result<usize, WafError> {
    route_keys(route).into_iter().map(|key| caddy_route_bytes(&caddy_route(route, key))).sum()
}


/// The reason the totals no longer fit the budget, if they do not.
pub fn overflow(upstreams: usize, bytes: usize, budget: &Budget) -> Option<&'static str> {
    if upstreams > budget.upstreams {
        Some(TOO_MANY_RENDERED)
    } else if bytes > budget.bytes {
        Some(TOO_MANY_BYTES)
    } else {
        None
    }
}


/// Keeps routes in file order while their upstreams and bytes fit `budget`; the first that does not fit and every later one are refused.
pub fn cap_rendered(placed: Vec<(usize, Route)>, budget: &Budget) -> Result<(Vec<Route>, Vec<Refusal>), WafError> {
    let mut upstreams = CATCH_ALL_UPSTREAMS;
    let mut bytes = serde_json::to_vec_pretty(&caddy_config(Vec::new()))?.len() + 1;
    let mut stopped: Option<&'static str> = None;
    let mut kept = Vec::new();
    let mut refused = Vec::new();
    let sizes = placed.iter().map(|(_, route)| route_bytes(route)).collect::<Result<Vec<_>, _>>()?;
    placed.into_iter().zip(sizes).for_each(|((index, route), size)| {
        upstreams += route_upstreams(&route);
        bytes += size;
        stopped = stopped.or_else(|| overflow(upstreams, bytes, budget));
        match stopped {
            Some(reason) => refused.push(Refusal {
                index,
                reason,
                shadowed_by: None,
            }),
            None => kept.push(route),
        }
    });
    Ok((kept, refused))
}
