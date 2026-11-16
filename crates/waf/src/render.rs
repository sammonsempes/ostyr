use crate::caddy::{
    Active, Apps, AutomaticHttps, CaddyConfig, CaddyRoute, Handle, Handler, HealthChecks, Http, Matcher, Passive, Server, StaticResponse, Upstream,
};
use crate::error::WafError;
use crate::limits::{
    FILE_LABEL, LISTEN_ADDRESS, MAX_FILE_BYTES, MAX_RENDERED_BYTES, MAX_RENDERED_UPSTREAMS, MAX_ROUTES, NOT_FOUND, PASSIVE_FAIL_SECONDS,
    PASSIVE_MAX_FAILS, SERVER_NAME, STATIC_RESPONSE,
};
use crate::model::{Budget, RawFile, Refusal, Rendered, Route, RouteCount};
use crate::order::{cap_rendered, place, route_keys};
use crate::validate::{convert_route, path_patterns};
use core_config::parse::{parse_document, read_text_capped};
use std::cmp::Reverse;
use std::collections::BTreeMap;
use std::io::Read;
use tracing::warn;


pub const REVERSE_PROXY: &str = "reverse_proxy";


/// One Caddy route for one path key of a route; the empty key matches every path of the hosts.
pub fn caddy_route(route: &Route, key: &str) -> CaddyRoute {
    let paths = if key.is_empty() { Vec::new() } else { path_patterns(key) };
    CaddyRoute {
        matchers: vec![Matcher {
            host: route.hosts.clone(),
            path: paths,
        }],
        handle: vec![Handle::Proxy(Handler {
            handler: REVERSE_PROXY,
            upstreams: route.backends.iter().map(|dial| Upstream { dial: dial.clone() }).collect(),
            health_checks: HealthChecks {
                active: Active {
                    uri: route.health_path.clone(),
                    interval: format!("{}s", route.interval_seconds),
                },
                passive: Passive {
                    fail_duration: format!("{PASSIVE_FAIL_SECONDS}s"),
                    max_fails: PASSIVE_MAX_FAILS,
                },
            },
        })],
    }
}


/// The final route: whatever no route matched gets an explicit 404.
pub fn not_found_route() -> CaddyRoute {
    CaddyRoute {
        matchers: Vec::new(),
        handle: vec![Handle::Answer(StaticResponse {
            handler: STATIC_RESPONSE,
            status_code: NOT_FOUND,
        })],
    }
}


/// Longer path keys first, ties in file order, then the catch-all: Caddy runs the first matching route only.
pub fn caddy_config(routes: Vec<Route>) -> CaddyConfig {
    let mut entries: Vec<(&Route, &str)> = routes
        .iter()
        .flat_map(|route| route_keys(route).into_iter().map(move |key| (route, key)))
        .collect();
    entries.sort_by_key(|(_, key)| Reverse(key.len()));
    let mut ordered: Vec<CaddyRoute> = entries.into_iter().map(|(route, key)| caddy_route(route, key)).collect();
    ordered.push(not_found_route());
    let server = Server {
        listen: vec![LISTEN_ADDRESS.to_string()],
        automatic_https: AutomaticHttps { disable: true },
        routes: ordered,
    };
    CaddyConfig {
        apps: Apps {
            http: Http {
                servers: BTreeMap::from([(SERVER_NAME.to_string(), server)]),
            },
        },
    }
}


/// The routes are counted before any is materialised; a route that fails a check is refused alone.
pub fn render_text(text: &str) -> Result<Rendered, WafError> {
    render_text_capped(
        text,
        &Budget {
            upstreams: MAX_RENDERED_UPSTREAMS,
            bytes: MAX_RENDERED_BYTES,
        },
    )
}


/// `render_text` with an explicit budget on the rendered upstreams and bytes.
pub fn render_text_capped(text: &str, budget: &Budget) -> Result<Rendered, WafError> {
    let counted: RouteCount = parse_document(text, FILE_LABEL)?;
    let count = counted.routes.len();
    if count > MAX_ROUTES {
        Err(WafError::TooManyRoutes { count, max: MAX_ROUTES })
    } else {
        let file: RawFile = parse_document(text, FILE_LABEL)?;
        let outcomes = file.routes.into_iter().map(convert_route).enumerate();
        let (accepted, rejected): (Vec<_>, Vec<_>) = outcomes.partition(|(_, outcome)| outcome.is_ok());
        let mut refused: Vec<Refusal> = rejected
            .into_iter()
            .filter_map(|(index, outcome)| {
                outcome.err().map(|reason| Refusal {
                    index,
                    reason,
                    shadowed_by: None,
                })
            })
            .collect();
        let converted = accepted
            .into_iter()
            .filter_map(|(index, outcome)| outcome.ok().map(|route| (index, route)))
            .collect();
        let (placed, shadowed) = place(converted);
        let (routes, over_cap) = cap_rendered(placed, budget)?;
        refused.extend(shadowed);
        refused.extend(over_cap);
        refused.sort_by_key(|refusal| refusal.index);
        refused.iter().for_each(|refusal| {
            let (index, reason, shadowed_by) = (refusal.index, refusal.reason, refusal.shadowed_by);
            warn!(index, reason, ?shadowed_by, "route refused");
        });
        Ok(Rendered {
            config: caddy_config(routes),
            refused,
        })
    }
}


/// Reads at most `MAX_FILE_BYTES` from `reader`.
pub fn render_reader(reader: &mut dyn Read) -> Result<Rendered, WafError> {
    let text = read_text_capped(reader, FILE_LABEL, MAX_FILE_BYTES)?;
    render_text(&text)
}
