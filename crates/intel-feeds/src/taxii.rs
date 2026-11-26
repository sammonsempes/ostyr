use crate::config::{validate_taxii, FeedConfig, TaxiiConfig};
use crate::error::{EntryError, TaxiiError};
use crate::files::read_trusted;
use crate::formats::{indicator_iocs, new_collector, record};
use crate::limits::{
    CURSOR_SKEW_SECONDS, MAX_DOCUMENT_BYTES, MAX_OBJECT_BYTES, MAX_TAXII_HEADER_BYTES, MAX_TAXII_IOCS, MAX_TAXII_NEXT_BYTES,
    MAX_TAXII_OBJECTS_PER_PAGE, TAXII_ACCEPT, TAXII_DATE_HEADER,
};
use crate::model::{Collector, FeedSummary, Ioc};
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use core_pg::password::read_password;
use serde::Deserialize;
use serde_json::value::RawValue;
use serde_json::Value;
use siem_ingest::clickhouse::{new_agent, MAX_CA_BYTES};
use siem_ingest::settings::is_loopback_http;
use std::io::{self, Read};
use std::time::Duration;
use time::format_description::well_known::Rfc3339;
use time::{Duration as TimeDuration, OffsetDateTime, UtcOffset};
use tracing::debug;
use ureq::Agent;
use zeroize::Zeroizing;


pub const BASIC_PREFIX: &str = "Basic ";


pub const AUTH_CAPACITY: usize = 4_096;


pub const STATUS_OK: u16 = 200;


pub const STATUS_UNAUTHORIZED: u16 = 401;


pub const STATUS_FORBIDDEN: u16 = 403;


pub const STATUS_NOT_FOUND: u16 = 404;


pub const STATUS_NOT_ACCEPTABLE: u16 = 406;


pub const STATUS_UNSUPPORTED_MEDIA: u16 = 415;


pub const STATUS_TOO_MANY: u16 = 429;


pub const STATUS_SERVER_FIRST: u16 = 500;


pub const STATUS_SERVER_LAST: u16 = 599;


pub const TYPE_FILTER: &str = "indicator";


pub const NEXT_EXTRA_CHARACTERS: &[u8] = b"._~=+-";


/// What became of the cursor after the poll; anything but `Advanced` keeps the previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CursorStatus {
    Advanced,
    Missing,
    Malformed,
    InFuture,
}


#[derive(Debug)]
pub struct PollOutcome {
    pub iocs: Vec<Ioc>,
    pub summary: FeedSummary,
    pub next_added_after: Option<OffsetDateTime>,
    pub cursor: CursorStatus,
    pub pages: u32,
    pub more_left: bool,
    pub next_refused: bool,
}


/// One answered page: the body (at most `MAX_DOCUMENT_BYTES`) and the raw `X-TAXII-Date-Added-Last` value.
#[derive(Debug)]
pub struct Page {
    pub body: Vec<u8>,
    pub last_added: Option<Vec<u8>>,
}


#[derive(Debug)]
pub struct PollState {
    pub collector: Collector,
    pub next: Option<String>,
    pub more: bool,
    pub stalled: bool,
    pub pages: u32,
    pub numbered: u64,
    pub last_added: Option<Vec<u8>>,
}


#[derive(Deserialize)]
pub struct Envelope<'a> {
    #[serde(default)]
    pub more: bool,
    #[serde(default)]
    pub next: Option<String>,
    #[serde(default, borrow)]
    pub objects: Option<&'a RawValue>,
}


#[derive(Debug, Clone, Copy, Default)]
pub struct ScanState {
    pub depth: usize,
    pub in_string: bool,
    pub escaped: bool,
    pub commas: usize,
}


/// Counts the commas of the top-level array byte by byte, so a page of tiny objects is refused before any element is materialised.
pub fn scan_byte(state: ScanState, byte: u8) -> Result<ScanState, TaxiiError> {
    if state.in_string {
        Ok(ScanState {
            escaped: !state.escaped && byte == b'\\',
            in_string: state.escaped || byte != b'"',
            ..state
        })
    } else {
        match byte {
            b'"' => Ok(ScanState { in_string: true, ..state }),
            b'[' | b'{' => Ok(ScanState {
                depth: state.depth.saturating_add(1),
                ..state
            }),
            b']' | b'}' => Ok(ScanState {
                depth: state.depth.saturating_sub(1),
                ..state
            }),
            b',' if state.depth == 1 && state.commas + 1 >= MAX_TAXII_OBJECTS_PER_PAGE => Err(TaxiiError::TooManyObjects),
            b',' if state.depth == 1 => Ok(ScanState {
                commas: state.commas + 1,
                ..state
            }),
            _ => Ok(state),
        }
    }
}


/// Category, line and column only: serde's own text repeats the offending value, which is server text.
pub fn envelope_error(error: serde_json::Error) -> TaxiiError {
    TaxiiError::Envelope {
        category: error.classify(),
        line: error.line(),
        column: error.column(),
    }
}


/// The elements of `objects`, as raw text, once their count is known to be within `MAX_TAXII_OBJECTS_PER_PAGE`.
pub fn page_objects(raw: Option<&RawValue>) -> Result<Vec<&RawValue>, TaxiiError> {
    raw.map_or(Ok(Vec::new()), |objects| {
        objects.get().bytes().try_fold(ScanState::default(), scan_byte)?;
        serde_json::from_str(objects.get()).map_err(envelope_error)
    })
}


/// One object: over `MAX_OBJECT_BYTES` it is skipped unread; otherwise the STIX indicator path decides.
pub fn object_iocs(feed: &FeedConfig, now: OffsetDateTime, text: &str) -> Result<Vec<Ioc>, EntryError> {
    if text.len() > MAX_OBJECT_BYTES {
        Err(EntryError::ObjectTooLarge)
    } else {
        let object: Value = serde_json::from_str(text).map_err(|_not_json| EntryError::NotAnObject)?;
        indicator_iocs(feed, now, &object)
    }
}


/// An opaque ASCII token, never a URL: it is sent back as one query value.
pub fn next_token_ok(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TAXII_NEXT_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || NEXT_EXTRA_CHARACTERS.contains(&byte))
}


/// Reads the envelope, counts and parses the objects, and decides whether another page can be asked for.
pub fn absorb_page(feed: &FeedConfig, now: OffsetDateTime, state: PollState, page: Page) -> Result<PollState, TaxiiError> {
    let envelope: Envelope = serde_json::from_slice(&page.body).map_err(envelope_error)?;
    let objects = page_objects(envelope.objects)?;
    let PollState {
        mut collector,
        pages,
        numbered,
        ..
    } = state;
    objects
        .iter()
        .zip(numbered + 1..)
        .for_each(|(raw, number)| record(&mut collector, number, object_iocs(feed, now, raw.get())));
    let next = envelope.next.filter(|token| next_token_ok(token));
    Ok(PollState {
        collector,
        stalled: envelope.more && next.is_none(),
        next,
        more: envelope.more,
        pages: pages + 1,
        numbered: numbered + objects.len() as u64,
        last_added: page.last_added,
    })
}


/// The HTTP Basic value; the pair and the header are zeroed on drop and sized so that neither reallocates.
pub fn basic_header(user: &str, password: &[u8]) -> Zeroizing<String> {
    let mut pair = Zeroizing::new(Vec::with_capacity(AUTH_CAPACITY));
    pair.extend_from_slice(user.as_bytes());
    pair.push(b':');
    pair.extend_from_slice(password);
    let mut header = Zeroizing::new(String::with_capacity(AUTH_CAPACITY));
    header.push_str(BASIC_PREFIX);
    STANDARD.encode_string(&*pair, &mut header);
    header
}


/// A fixed error per class; the server's text is never read.
pub fn status_error(status: u16) -> TaxiiError {
    match status {
        STATUS_UNAUTHORIZED | STATUS_FORBIDDEN => TaxiiError::Unauthorized,
        STATUS_NOT_FOUND => TaxiiError::UnknownCollection,
        STATUS_NOT_ACCEPTABLE | STATUS_UNSUPPORTED_MEDIA => TaxiiError::VersionRefused,
        STATUS_TOO_MANY | STATUS_SERVER_FIRST..=STATUS_SERVER_LAST => TaxiiError::Unavailable,
        other => TaxiiError::Status(other),
    }
}


/// A read failure keeps its kind only; a ureq error wrapped by the reader goes through `ureq_error`.
pub fn body_error(error: io::Error) -> TaxiiError {
    let wrapped = error.get_ref().and_then(|inner| inner.downcast_ref::<ureq::Error>());
    wrapped.map_or(TaxiiError::Io { kind: error.kind() }, ureq_error)
}


/// Maps a ureq error to a fixed variant; ureq's text can hold the peer's certificate names, so none of it is kept.
pub fn ureq_error(error: &ureq::Error) -> TaxiiError {
    match error {
        ureq::Error::Timeout(_) => TaxiiError::Timeout,
        ureq::Error::Tls(_) | ureq::Error::Pem(_) | ureq::Error::Rustls(_) => TaxiiError::Tls,
        ureq::Error::HostNotFound | ureq::Error::ConnectionFailed => TaxiiError::Connect,
        ureq::Error::Io(inner) => TaxiiError::Io { kind: inner.kind() },
        _ => TaxiiError::Protocol,
    }
}


pub fn transport_error(error: ureq::Error) -> TaxiiError {
    ureq_error(&error)
}


/// The query of one page request; `next` rides as a value of its own and the filters are sent again with it.
pub fn request_pairs(config: &TaxiiConfig, added_after: Option<&str>, next: Option<&str>) -> Vec<(&'static str, String)> {
    added_after
        .map(|cursor| ("added_after", cursor.to_owned()))
        .into_iter()
        .chain([("limit", config.page_limit.to_string()), ("match[type]", TYPE_FILTER.to_owned())])
        .chain(next.map(|token| ("next", token.to_owned())))
        .collect()
}


pub fn collection_url(config: &TaxiiConfig) -> String {
    format!("{}/collections/{}/objects/", config.api_root.trim_end_matches('/'), config.collection)
}


/// One request under what is left of the global deadline; the body is read through `take(MAX_DOCUMENT_BYTES + 1)`.
pub fn fetch_page(
    agent: &Agent,
    config: &TaxiiConfig,
    auth: &str,
    pairs: &[(&'static str, String)],
    remaining: Duration,
) -> Result<Page, TaxiiError> {
    if remaining.is_zero() {
        Err(TaxiiError::Timeout)
    } else {
        let base = agent
            .get(collection_url(config))
            .header("Accept", TAXII_ACCEPT)
            .header("Authorization", auth);
        let request = pairs.iter().fold(base, |builder, (key, value)| builder.query(*key, value));
        let mut response = request.config().timeout_global(Some(remaining)).build().call().map_err(transport_error)?;
        let status = response.status().as_u16();
        if status == STATUS_OK {
            let last_added = response.headers().get(TAXII_DATE_HEADER).map(|value| value.as_bytes().to_vec());
            let limit = MAX_DOCUMENT_BYTES as u64 + 1;
            let mut body = Vec::new();
            response
                .body_mut()
                .with_config()
                .limit(limit)
                .reader()
                .take(limit)
                .read_to_end(&mut body)
                .map_err(body_error)?;
            if body.len() > MAX_DOCUMENT_BYTES {
                Err(TaxiiError::PageTooLarge)
            } else {
                Ok(Page { body, last_added })
            }
        } else {
            Err(status_error(status))
        }
    }
}


/// RFC 3339 in UTC, a writable year, not more than `CURSOR_SKEW_SECONDS` after `now`; anything else is a counted refusal.
pub fn parse_cursor(header: &[u8], now: OffsetDateTime) -> Result<OffsetDateTime, CursorStatus> {
    let text = if header.len() > MAX_TAXII_HEADER_BYTES {
        Err(CursorStatus::Malformed)
    } else {
        std::str::from_utf8(header).map_err(|_not_utf8| CursorStatus::Malformed)
    }?;
    let utc = OffsetDateTime::parse(text.trim(), &Rfc3339)
        .map_err(|_not_rfc3339| CursorStatus::Malformed)?
        .checked_to_offset(UtcOffset::UTC)
        .filter(|candidate| candidate.format(&Rfc3339).is_ok())
        .ok_or(CursorStatus::Malformed)?;
    if utc > now.saturating_add(TimeDuration::seconds(CURSOR_SKEW_SECONDS)) {
        Err(CursorStatus::InFuture)
    } else {
        Ok(utc)
    }
}


/// The last page's header decides; absent, malformed or in the future keeps the previous cursor and says why.
pub fn settle_cursor(previous: Option<OffsetDateTime>, last: Option<&[u8]>, now: OffsetDateTime) -> (Option<OffsetDateTime>, CursorStatus) {
    last.map_or((previous, CursorStatus::Missing), |header| {
        parse_cursor(header, now).map_or_else(|status| (previous, status), |cursor| (Some(cursor), CursorStatus::Advanced))
    })
}


/// Sent in UTC with a `Z` (a server may not read `+02:00` in a query), and only when it can be written as RFC 3339.
pub fn utc_cursor(cursor: OffsetDateTime) -> Result<String, TaxiiError> {
    cursor
        .checked_to_offset(UtcOffset::UTC)
        .ok_or(TaxiiError::CursorRange)?
        .format(&Rfc3339)
        .map_err(TaxiiError::Cursor)
}


/// Another page is asked for only while the server says `more`, its `next` was usable, and fewer than `cap` IOCs are held.
pub fn has_room(state: &PollState, cap: usize) -> bool {
    state.more && !state.stalled && state.collector.iocs.len() < cap
}


/// Follows `next` while the server says `more`, at most `max_pages` pages and `MAX_TAXII_IOCS` IOCs under one deadline; `more_left` says it stopped early.
pub fn poll_collection(
    agent: &Agent,
    feed: &FeedConfig,
    password: &[u8],
    added_after: Option<OffsetDateTime>,
    now: OffsetDateTime,
    elapsed: &dyn Fn() -> Duration,
) -> Result<PollOutcome, TaxiiError> {
    let config = feed.taxii.as_ref().ok_or(TaxiiError::NoSection)?;
    validate_taxii(config)?;
    let after = added_after.map(utc_cursor).transpose()?;
    let auth = basic_header(&config.user, password);
    let budget = Duration::from_millis(config.timeout_ms);
    let mut state = PollState {
        collector: new_collector(feed),
        next: None,
        more: true,
        stalled: false,
        pages: 0,
        numbered: 0,
        last_added: None,
    };
    while state.pages < config.max_pages && has_room(&state, MAX_TAXII_IOCS) {
        let pairs = request_pairs(config, after.as_deref(), state.next.as_deref());
        let page = fetch_page(agent, config, &auth, &pairs, budget.saturating_sub(elapsed()))?;
        state = absorb_page(feed, now, state, page)?;
    }
    let (next_added_after, cursor) = settle_cursor(added_after, state.last_added.as_deref(), now);
    let (pages, more_left, next_refused) = (state.pages, state.more, state.stalled);
    debug!(feed = feed.name, pages, more_left, next_refused, "taxii poll finished");
    Ok(PollOutcome {
        iocs: state.collector.iocs,
        summary: state.collector.summary,
        next_added_after,
        cursor,
        pages,
        more_left,
        next_refused,
    })
}


/// The CA file is read again at every poll, through an `O_NONBLOCK` handle that must be a regular file.
pub fn taxii_agent(config: &TaxiiConfig) -> Result<Agent, TaxiiError> {
    let pem = config
        .ca_file
        .as_deref()
        .map(|path| read_trusted(path, MAX_CA_BYTES).map_err(TaxiiError::CaFile))
        .transpose()?;
    new_agent(pem.as_deref().map(Vec::as_slice), !is_loopback_http(&config.api_root)).map_err(TaxiiError::Agent)
}


/// Settings are validated first, then the password and CA are read (core-pg's owner and mode rules), then the collection is polled.
pub fn poll_feed(
    feed: &FeedConfig,
    added_after: Option<OffsetDateTime>,
    now: OffsetDateTime,
    elapsed: &dyn Fn() -> Duration,
) -> Result<PollOutcome, TaxiiError> {
    let config = feed.taxii.as_ref().ok_or(TaxiiError::NoSection)?;
    validate_taxii(config)?;
    let password = read_password(&config.password_file).map_err(TaxiiError::Password)?;
    let agent = taxii_agent(config)?;
    poll_collection(&agent, feed, &password, added_after, now, elapsed)
}
