use crate::caddy::{Active, Apps, AutomaticHttps, CaddyConfig, CaddyRoute, Handler, HealthChecks, Http, Matcher, Passive, Server, Upstream};
use crate::error::WafError;
use crate::limits::{FILE_LABEL, LISTEN_ADDRESS, MAX_FILE_BYTES, MAX_ROUTES, PASSIVE_FAIL_SECONDS, PASSIVE_MAX_FAILS, SERVER_NAME};
use crate::model::{RawFile, Refusal, Rendered, Route, RouteCount};
use crate::validate::convert_route;
use core_config::parse::{parse_document, read_text_capped};
use std::collections::BTreeMap;
use std::io::Read;
use tracing::warn;


pub const REVERSE_PROXY: &str = "reverse_proxy";


pub fn caddy_route(route: Route) -> CaddyRoute {
    CaddyRoute {
        matchers: vec![Matcher {
            host: route.hosts,
            path: route.paths,
        }],
        handle: vec![Handler {
            handler: REVERSE_PROXY,
            upstreams: route.backends.into_iter().map(|dial| Upstream { dial }).collect(),
            health_checks: HealthChecks {
                active: Active {
                    uri: route.health_path,
                    interval: format!("{}s", route.interval_seconds),
                },
                passive: Passive {
                    fail_duration: format!("{PASSIVE_FAIL_SECONDS}s"),
                    max_fails: PASSIVE_MAX_FAILS,
                },
            },
        }],
    }
}


pub fn caddy_config(routes: Vec<Route>) -> CaddyConfig {
    let server = Server {
        listen: vec![LISTEN_ADDRESS.to_string()],
        automatic_https: AutomaticHttps { disable: true },
        routes: routes.into_iter().map(caddy_route).collect(),
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
    let counted: RouteCount = parse_document(text, FILE_LABEL)?;
    let count = counted.routes.len();
    if count > MAX_ROUTES {
        Err(WafError::TooManyRoutes { count, max: MAX_ROUTES })
    } else {
        let file: RawFile = parse_document(text, FILE_LABEL)?;
        let outcomes = file.routes.into_iter().map(convert_route).enumerate();
        let (accepted, rejected): (Vec<_>, Vec<_>) = outcomes.partition(|(_, outcome)| outcome.is_ok());
        let refused: Vec<Refusal> = rejected
            .into_iter()
            .filter_map(|(index, outcome)| outcome.err().map(|reason| Refusal { index, reason }))
            .collect();
        refused.iter().for_each(|refusal| {
            let (index, reason) = (refusal.index, refusal.reason);
            warn!(index, reason, "route refused");
        });
        let routes = accepted.into_iter().filter_map(|(_, outcome)| outcome.ok()).collect();
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
