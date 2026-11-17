use crate::caddy::{
    Active, Apps, Authorities, AutomaticHttps, Automation, CaddyConfig, CaddyRoute, ConnectionPolicy, Handle, Handler, Headers, HealthChecks, Http,
    IssuerConfig, LocalAuthority, Matcher, Passive, PkiApp, Policy, RequestHeaders, Server, StaticResponse, TlsApp, Upstream,
};
use crate::error::WafError;
use crate::limits::{
    ACME_MODULE, FILE_LABEL, HSTS_HEADER, INTERNAL_MODULE, LISTEN_ADDRESS, LOOP_DETECTED, MAX_FILE_BYTES, MAX_RENDERED_BYTES, MAX_RENDERED_UPSTREAMS,
    MAX_ROUTES, NOT_FOUND, PASSIVE_FAIL_SECONDS, PASSIVE_MAX_FAILS, PROTOCOL_MIN, PROXIED_HEADER, PROXIED_VALUE, SERVER_NAME, STATIC_RESPONSE,
    TLS_LISTEN_ADDRESS,
};
use crate::model::{Budget, Issuer, RawFile, Refusal, Rendered, Route, RouteCount, Tls};
use crate::order::{cap_rendered, place, route_keys};
use crate::tls::check_tls;
use crate::validate::{convert_route, path_patterns};
use core_config::parse::{parse_document, read_text_capped};
use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use tracing::warn;


pub const REVERSE_PROXY: &str = "reverse_proxy";


/// One Caddy route for one path key of a route; the empty key matches every path of the hosts.
pub fn caddy_route(route: &Route, key: &str, hsts: Option<&str>) -> CaddyRoute {
    let paths = if key.is_empty() { Vec::new() } else { path_patterns(key) };
    CaddyRoute {
        matchers: vec![Matcher {
            host: route.hosts.clone(),
            path: paths,
            header: BTreeMap::new(),
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
            headers: Headers {
                request: RequestHeaders {
                    set: BTreeMap::from([(PROXIED_HEADER.to_string(), vec![PROXIED_VALUE.to_string()])]),
                },
                response: hsts.map(|value| RequestHeaders {
                    set: BTreeMap::from([(HSTS_HEADER.to_string(), vec![value.to_string()])]),
                }),
            },
        })],
    }
}


/// The first route: a request already proxied once by this server answers 508 with no body, so no loop can run.
pub fn loop_route() -> CaddyRoute {
    CaddyRoute {
        matchers: vec![Matcher {
            host: Vec::new(),
            path: Vec::new(),
            header: BTreeMap::from([(PROXIED_HEADER.to_string(), vec![PROXIED_VALUE.to_string()])]),
        }],
        handle: vec![Handle::Answer(StaticResponse {
            handler: STATIC_RESPONSE,
            status_code: LOOP_DETECTED,
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


/// The ACME or internal issuer of the single automation policy.
pub fn issuer_config(issuer: &Issuer) -> IssuerConfig {
    match issuer {
        Issuer::Acme { directory, email, ca_root } => IssuerConfig {
            module: ACME_MODULE,
            ca: Some(directory.clone()),
            email: Some(email.clone()),
            trusted_roots_pem_files: ca_root.iter().map(|root| root.name.clone()).collect(),
        },
        Issuer::Internal => IssuerConfig {
            module: INTERNAL_MODULE,
            ca: None,
            email: None,
            trusted_roots_pem_files: Vec::new(),
        },
    }
}


/// The `tls` app: one policy whose subjects are exactly the hosts of the accepted routes, so no other name can trigger issuance.
pub fn tls_app(tls: &Tls, routes: &[Route]) -> TlsApp {
    let subjects: BTreeSet<String> = routes.iter().flat_map(|route| route.hosts.iter().cloned()).collect();
    let policies = if subjects.is_empty() {
        Vec::new()
    } else {
        vec![Policy {
            subjects: subjects.into_iter().collect(),
            issuers: vec![issuer_config(&tls.issuer)],
        }]
    };
    TlsApp {
        automation: Automation { policies },
    }
}


/// Caddy's `local` CA installs its root into the host trust store by default; the entry point's storage must never be able to mint trusted roots.
pub fn no_trust_install() -> PkiApp {
    PkiApp {
        certificate_authorities: Authorities {
            local: LocalAuthority { install_trust: false },
        },
    }
}


/// Longer path keys first, ties in file order, then the catch-all: Caddy runs the first matching route only.
pub fn caddy_config(routes: Vec<Route>, tls: Option<&Tls>) -> CaddyConfig {
    let hsts = tls.and_then(|value| value.hsts.as_deref());
    let mut entries: Vec<(&Route, &str)> = routes
        .iter()
        .flat_map(|route| route_keys(route).into_iter().map(move |key| (route, key)))
        .collect();
    entries.sort_by_key(|(_, key)| Reverse(key.len()));
    let mut ordered: Vec<CaddyRoute> = vec![loop_route()];
    ordered.extend(entries.into_iter().map(|(route, key)| caddy_route(route, key, hsts)));
    ordered.push(not_found_route());
    let secured = tls.is_some();
    let server = Server {
        listen: vec![(if secured { TLS_LISTEN_ADDRESS } else { LISTEN_ADDRESS }).to_string()],
        automatic_https: AutomaticHttps {
            disable: (!secured).then_some(true),
            disable_redirects: secured.then_some(false),
        },
        tls_connection_policies: if secured {
            vec![ConnectionPolicy { protocol_min: PROTOCOL_MIN }]
        } else {
            Vec::new()
        },
        routes: ordered,
    };
    let tls_section = tls.map(|value| tls_app(value, &routes));
    CaddyConfig {
        apps: Apps {
            http: Http {
                servers: BTreeMap::from([(SERVER_NAME.to_string(), server)]),
            },
            tls: tls_section,
            pki: tls.map(|_| no_trust_install()),
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
        let tls = file.tls.map(check_tls).transpose()?;
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
        let (routes, over_cap) = cap_rendered(placed, budget, tls.as_ref())?;
        refused.extend(shadowed);
        refused.extend(over_cap);
        refused.sort_by_key(|refusal| refusal.index);
        refused.iter().for_each(|refusal| {
            let (index, reason, shadowed_by) = (refusal.index, refusal.reason, refusal.shadowed_by);
            warn!(index, reason, ?shadowed_by, "route refused");
        });
        let ca_root = tls.as_ref().and_then(|value| match &value.issuer {
            Issuer::Acme { ca_root, .. } => ca_root.clone(),
            Issuer::Internal => None,
        });
        Ok(Rendered {
            config: caddy_config(routes, tls.as_ref()),
            ca_root,
            refused,
        })
    }
}


/// Reads at most `MAX_FILE_BYTES` from `reader`.
pub fn render_reader(reader: &mut dyn Read) -> Result<Rendered, WafError> {
    let text = read_text_capped(reader, FILE_LABEL, MAX_FILE_BYTES)?;
    render_text(&text)
}
