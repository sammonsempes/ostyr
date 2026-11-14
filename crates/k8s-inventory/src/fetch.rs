use crate::access::check_read_only;
use crate::error::{FetchError, ParseError};
use crate::inventory::{build_inventory, Inventory};
use crate::limits::{Limits, PageLimits};
use crate::model::{NodeItem, Page, PodItem};
use crate::pages::{merge_node_pages, merge_pod_pages, page_next, page_size, remaining_budget};
use crate::parse::{parse_nodes_page, parse_pods_page};
use crate::settings::{limits_of, load_settings, namespaces_of, page_limits_of, run_bytes_of, validate_settings, FetchSettings};
use crate::types::PageParser;
use core_pg::password::{read_limited, read_password};
use std::io::Read;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use ureq::http::Response;
use ureq::tls::{Certificate, RootCerts, TlsConfig};
use ureq::{Agent, Body};
use zeroize::Zeroizing;


pub const PODS_PATH: &str = "/api/v1/pods";


pub const NODES_PATH: &str = "/api/v1/nodes";


pub const STATUS_OK: u16 = 200;


pub const STATUS_GONE: u16 = 410;


pub const MAX_CA_BYTES: u64 = 65_536;


pub const AUTHORIZATION: &str = "Authorization";


pub const BEARER_PREFIX: &str = "Bearer ";


pub const JSON_TYPE: &str = "application/json";


/// One run: the agent, the bearer header value, the deadline and the bytes the run may still read. No `Debug`: the header value is the token.
pub struct Session {
    pub agent: Agent,
    pub api_url: String,
    pub bearer: Zeroizing<String>,
    pub started: Instant,
    pub timeout: Duration,
    pub bytes_left: u64,
}


/// The status and, for a 2xx answer only, the body; any other body is never read.
#[derive(Debug)]
pub struct Reply {
    pub status: u16,
    pub body: Vec<u8>,
}


pub fn pods_page(body: &[u8], limits: &Limits, budget: usize) -> Result<Page<PodItem>, ParseError> {
    parse_pods_page(body, limits, budget)
}


pub fn nodes_page(body: &[u8], limits: &Limits, budget: usize) -> Result<Page<NodeItem>, ParseError> {
    parse_nodes_page(body, limits, budget)
}


/// No redirect, no environment proxy, https only, and only the cluster CA as root.
pub fn new_agent(ca_pem: &[u8]) -> Result<Agent, FetchError> {
    let certificate = Certificate::from_pem(ca_pem).map_err(FetchError::CaInvalid)?;
    let tls = TlsConfig::builder().root_certs(RootCerts::Specific(Arc::new(vec![certificate]))).build();
    let config = Agent::config_builder()
        .http_status_as_error(false)
        .max_redirects(0)
        .https_only(true)
        .proxy(None)
        .tls_config(tls)
        .build();
    Ok(Agent::new_with_config(config))
}


/// Printable ASCII without a space: anything else could not be a header value and is refused without echoing it.
pub fn bearer_of(token: &[u8]) -> Result<Zeroizing<String>, FetchError> {
    if token.iter().all(u8::is_ascii_graphic) {
        let mut header = Zeroizing::new(String::from(BEARER_PREFIX));
        header.push_str(&String::from_utf8_lossy(token));
        Ok(header)
    } else {
        Err(FetchError::TokenEncoding)
    }
}


/// The token and the CA are read through core-pg's checked readers (regular file, bounded) at every run.
pub fn open_session(settings: &FetchSettings) -> Result<Session, FetchError> {
    validate_settings(settings)?;
    let token = read_password(&settings.token_file).map_err(FetchError::Token)?;
    let ca = read_limited(&settings.ca_file, MAX_CA_BYTES).map_err(FetchError::CaFile)?;
    Ok(Session {
        agent: new_agent(&ca)?,
        api_url: settings.api_url.clone(),
        bearer: bearer_of(&token)?,
        started: Instant::now(),
        timeout: Duration::from_millis(settings.timeout_ms),
        bytes_left: run_bytes_of(settings),
    })
}


/// Each request gets the time left; a spent deadline sends nothing.
pub fn time_left(session: &Session) -> Result<Duration, FetchError> {
    let left = session.timeout.saturating_sub(session.started.elapsed());
    if left.is_zero() {
        Err(FetchError::Deadline)
    } else {
        Ok(left)
    }
}


/// A 2xx body is read through `take(min(cap, bytes_left) + 1)`: over `cap` is `TooLarge`, over the run budget is `RunTooLarge`.
pub fn read_reply(session: &mut Session, response: Response<Body>, cap: u64) -> Result<Reply, FetchError> {
    let status = response.status();
    if status.is_success() {
        let allowed = cap.min(session.bytes_left);
        let mut body = Vec::new();
        response
            .into_body()
            .into_reader()
            .take(allowed.saturating_add(1))
            .read_to_end(&mut body)
            .map_err(FetchError::Body)?;
        let length = body.len() as u64;
        if length > allowed && session.bytes_left < cap {
            Err(FetchError::RunTooLarge { max: session.bytes_left })?;
        }
        if length > allowed {
            Err(FetchError::TooLarge { max: cap })?;
        }
        session.bytes_left -= length;
        Ok(Reply {
            status: status.as_u16(),
            body,
        })
    } else {
        Ok(Reply {
            status: status.as_u16(),
            body: Vec::new(),
        })
    }
}


pub fn get_reply(session: &mut Session, path: &str, query: &[(&str, &str)], cap: u64) -> Result<Reply, FetchError> {
    let left = time_left(session)?;
    let url = format!("{}{path}", session.api_url);
    let request = query
        .iter()
        .fold(session.agent.get(&url), |builder, (name, value)| builder.query(*name, *value));
    let response = request
        .header(AUTHORIZATION, session.bearer.as_str())
        .config()
        .timeout_global(Some(left))
        .build()
        .call()
        .map_err(FetchError::Transport)?;
    read_reply(session, response, cap)
}


pub fn post_reply(session: &mut Session, path: &str, body: &str, cap: u64) -> Result<Reply, FetchError> {
    let left = time_left(session)?;
    let url = format!("{}{path}", session.api_url);
    let response = session
        .agent
        .post(&url)
        .header(AUTHORIZATION, session.bearer.as_str())
        .header("Content-Type", JSON_TYPE)
        .config()
        .timeout_global(Some(left))
        .build()
        .send(body)
        .map_err(FetchError::Transport)?;
    read_reply(session, response, cap)
}


/// `410 Gone` (an expired continue token) is `Incomplete`; any other non-200 status is its number only.
pub fn fetch_page<Item>(
    session: &mut Session,
    path: &str,
    limit: usize,
    token: Option<&str>,
    limits: &Limits,
    budget: usize,
    parse: PageParser<Item>,
) -> Result<Page<Item>, FetchError> {
    let limit_text = limit.to_string();
    let mut query = vec![("limit", limit_text.as_str())];
    if let Some(continue_token) = token {
        query.push(("continue", continue_token));
    }
    let reply = get_reply(session, path, &query, limits.max_bytes)?;
    match reply.status {
        STATUS_OK => Ok(parse(&reply.body, limits, budget)?),
        STATUS_GONE => Err(ParseError::Incomplete)?,
        status => Err(FetchError::Status { status }),
    }
}


/// Pages until one has no token or `max_pages` is spent; each request carries exactly the previous page's token. Merging decides completeness.
pub fn list_pages<Item>(
    session: &mut Session,
    path: &str,
    limits: &Limits,
    page_limits: &PageLimits,
    limit: usize,
    parse: PageParser<Item>,
) -> Result<Vec<Page<Item>>, FetchError> {
    (0..page_limits.max_pages).try_fold(Vec::new(), |mut pages: Vec<Page<Item>>, _| {
        if pages.last().is_none_or(|last| page_next(last).is_some()) {
            let budget = remaining_budget(&pages, page_limits);
            let token = pages.last().and_then(page_next).map(str::to_owned);
            pages.push(fetch_page(session, path, limit, token.as_deref(), limits, budget, parse)?);
        }
        Ok(pages)
    })
}


/// The access check first, then pods, then nodes; a refused or partial run gives no inventory.
pub fn fetch_with(session: &mut Session, settings: &FetchSettings) -> Result<Inventory, FetchError> {
    let limits = limits_of(settings);
    let page_limits = page_limits_of(settings);
    let limit = settings.page_size.unwrap_or_else(|| page_size(&limits));
    check_read_only(session, namespaces_of(settings))?;
    let pods = merge_pod_pages(list_pages(session, PODS_PATH, &limits, &page_limits, limit, pods_page)?, &page_limits)?;
    let nodes = merge_node_pages(list_pages(session, NODES_PATH, &limits, &page_limits, limit, nodes_page)?, &page_limits)?;
    Ok(build_inventory(&settings.tenant, &settings.cluster, pods, nodes)?)
}


/// One run from a settings file; a failure is logged with its fixed text.
pub fn fetch_inventory(settings_file: &Path) -> Result<Inventory, FetchError> {
    let outcome =
        load_settings(settings_file).and_then(|settings| open_session(&settings).and_then(|mut session| fetch_with(&mut session, &settings)));
    if let Err(error) = &outcome {
        let text = error.to_string();
        tracing::warn!("k8s inventory fetch refused: {text}");
    }
    outcome
}
