use crate::error::{unavailable, ApiFailure};
use crate::model::{
    Alert, AlertPage, ApiClient, AssetDetailView, AssetPageView, CaseDetailView, CasePageView, CertDetailView, CertListView, CommentView,
    FindingsView, RiskDetailView, RiskListView,
};
use data_encoding::BASE64URL_NOPAD;
use ecs_normalise::suricata::{clean_identity, is_unsafe, MAX_FIELD_CHARS};
use reqwest::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::{Method, Response, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use serde_json::value::RawValue;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout_at, Instant};
use unicode_bidi::{BidiInfo, Level};
use unicode_normalization::is_nfc;
use url::form_urlencoded::{byte_serialize, Serializer};


pub const MAX_BODY_BYTES: usize = 1_048_576;


pub const MAX_BODY_READS: usize = 4096;


pub const MAX_ITEMS: usize = 100;


pub const MAX_TOKEN_BYTES: usize = 4096;


pub const MAX_CURSOR_CHARS: usize = 512;


pub const MAX_ASSET_ID_BYTES: usize = 512;


pub const MAX_ASSET_CURSOR_CHARS: usize = 768;


pub const MAX_ASSET_KEYS: usize = 64;


pub const MAX_ASSET_ATTRIBUTES: usize = 500;


pub const RISK_KINDS: [&str; 2] = ["host", "user"];


pub const RISK_LIMIT: u32 = 100;


pub const MAX_RISK_ENTITIES: usize = 500;


pub const MAX_RISK_VALUE: u64 = 100;


pub const CERT_LIMIT: u32 = 100;


pub const MAX_CERT_CURSOR_CHARS: usize = 85;


pub const MAX_CERT_SIGHTINGS: usize = 500;


pub const SECONDS_PER_DAY: i64 = 86_400;


pub const CERT_FILTERS: [&str; 3] = ["all", "30", "90"];


pub const ID_LENGTH: usize = 64;


pub const MAX_CASE_ID_CHARS: usize = 128;


pub const MAX_COMMENT_CHARS: usize = 8_192;


pub const CONFLICT_CODES: [(&str, &str); 4] = [
    ("transition_not_allowed", "error_transition_not_allowed"),
    ("resolution_required", "error_resolution_required"),
    ("case_changed", "error_case_changed"),
    ("full", "error_comment_full"),
];


pub const FORWARDED: HeaderName = HeaderName::from_static("forwarded");


pub const JSON_TYPE: HeaderValue = HeaderValue::from_static("application/json");


#[derive(Debug, Deserialize)]
pub struct TokenReply {
    pub token: String,
}


#[derive(Debug, Deserialize)]
pub struct ErrorDetail {
    pub code: String,
}


#[derive(Debug, Deserialize)]
pub struct ErrorEnvelope {
    pub error: ErrorDetail,
}


pub fn valid_id(id: &str) -> bool {
    id.len() == ID_LENGTH && id.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}


/// A case id that may become a link or an API path: ASCII alphanumeric first, then alphanumerics and `._-`, at most 128 characters.
pub fn valid_case_id(id: &str) -> bool {
    id.len() <= MAX_CASE_ID_CHARS
        && id.bytes().next().is_some_and(|first| first.is_ascii_alphanumeric())
        && id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'_' || byte == b'-')
}


/// The opaque cursor alphabet of the API contract: URL-safe base64.
pub fn valid_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= MAX_CURSOR_CHARS
        && cursor
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'=')
}


pub fn valid_token(token: &str) -> bool {
    !token.is_empty() && token.len() <= MAX_TOKEN_BYTES && token.bytes().all(|byte| byte.is_ascii_graphic())
}


pub fn classify(status: StatusCode) -> Result<(), ApiFailure> {
    match status {
        success if success.is_success() => Ok(()),
        StatusCode::BAD_REQUEST => Err(ApiFailure::BadRequest),
        StatusCode::UNAUTHORIZED => Err(ApiFailure::Unauthorized),
        StatusCode::FORBIDDEN => Err(ApiFailure::Forbidden),
        StatusCode::NOT_FOUND => Err(ApiFailure::NotFound),
        StatusCode::TOO_MANY_REQUESTS => Err(ApiFailure::Throttled),
        other => Err(ApiFailure::Status(other.as_u16())),
    }
}


/// Reads at most `MAX_BODY_BYTES` in at most `MAX_BODY_READS` chunks; anything longer is refused, never cut.
pub async fn read_capped(mut response: Response) -> Result<Vec<u8>, ApiFailure> {
    let mut body = Vec::new();
    let mut finished = false;
    let mut reads = usize::MIN;
    while !finished && reads < MAX_BODY_READS && body.len() <= MAX_BODY_BYTES {
        let chunk = response.chunk().await.map_err(unavailable)?;
        finished = chunk.is_none();
        chunk.iter().for_each(|piece| body.extend_from_slice(piece));
        reads += 1;
    }
    if finished {
        Ok(body)
    } else {
        Err(ApiFailure::TooLarge)
    }
}


/// The `Forwarded` element the API reads from a trusted forwarder: an IPv4 literal, or a quoted bracketed IPv6 literal.
pub fn forwarded_value(source: IpAddr) -> String {
    match source.to_canonical() {
        IpAddr::V4(address) => format!("for={address}"),
        IpAddr::V6(address) => format!("for=\"[{address}]\""),
    }
}


pub fn header_from_text(text: &str) -> Result<HeaderValue, ApiFailure> {
    HeaderValue::from_str(text).map_err(|_invalid| ApiFailure::Malformed("forwarded address"))
}


/// A slot of `permits` before the instant `until`; a closed or exhausted semaphore is `Throttled`.
pub async fn acquire(permits: &Arc<Semaphore>, until: Instant) -> Result<OwnedSemaphorePermit, ApiFailure> {
    timeout_at(until, permits.clone().acquire_owned())
        .await
        .map_err(|_elapsed| ApiFailure::Throttled)?
        .map_err(|_closed| ApiFailure::Throttled)
}


/// One bounded pool of calls: the wait for a slot and the request share the deadline, and the slot is held until the body is read.
pub async fn call(
    client: &ApiClient,
    source: IpAddr,
    method: Method,
    path: &str,
    token: Option<&SecretString>,
    body: Option<String>,
) -> Result<Vec<u8>, ApiFailure> {
    call_until(client, Instant::now() + client.deadline, source, method, path, token, body).await
}


/// `call` against an instant computed once by the caller, so several waits of one operation share one deadline.
pub async fn call_until(
    client: &ApiClient,
    until: Instant,
    source: IpAddr,
    method: Method,
    path: &str,
    token: Option<&SecretString>,
    body: Option<String>,
) -> Result<Vec<u8>, ApiFailure> {
    let _permit = acquire(&client.permits, until).await?;
    let mut request = client
        .http
        .request(method, format!("{}{path}", client.base))
        .timeout(until.saturating_duration_since(Instant::now()))
        .header(FORWARDED, header_from_text(&forwarded_value(source))?);
    request = token.iter().fold(request, |pending, secret| pending.bearer_auth(secret.expose_secret()));
    request = body
        .into_iter()
        .fold(request, |pending, text| pending.header(CONTENT_TYPE, JSON_TYPE).body(text));
    let response = request.send().await.map_err(unavailable)?;
    match response.status() {
        StatusCode::CONFLICT => Err(conflict_failure(&read_capped(response).await?)),
        status => {
            classify(status)?;
            read_capped(response).await
        }
    }
}


/// A `409` is one of the fixed codes of the cases module, kept as the key of our own text; anything else is a plain status.
pub fn conflict_failure(body: &[u8]) -> ApiFailure {
    serde_json::from_slice::<ErrorEnvelope>(body)
        .ok()
        .and_then(|envelope| {
            CONFLICT_CODES
                .iter()
                .find(|(code, _)| *code == envelope.error.code)
                .map(|(_, key)| ApiFailure::Conflict(key))
        })
        .unwrap_or(ApiFailure::Status(StatusCode::CONFLICT.as_u16()))
}


/// `POST /auth/login`: the token goes straight into a secret and nothing of the answer is kept otherwise; logins hold at most half of the pool.
pub async fn login(client: &ApiClient, source: IpAddr, username: &str, password: &str, totp_code: Option<&str>) -> Result<SecretString, ApiFailure> {
    let until = Instant::now() + client.deadline;
    let _slot = acquire(&client.login_permits, until).await?;
    let body = json!({ "username": username, "password": password, "totp_code": totp_code }).to_string();
    let bytes = call_until(client, until, source, Method::POST, "auth/login", None, Some(body)).await?;
    let reply: TokenReply = serde_json::from_slice(&bytes)?;
    if valid_token(&reply.token) {
        Ok(SecretString::from(reply.token))
    } else {
        Err(ApiFailure::Malformed("token"))
    }
}


pub async fn logout(client: &ApiClient, source: IpAddr, token: &SecretString) -> Result<(), ApiFailure> {
    call(client, source, Method::POST, "auth/logout", Some(token), None)
        .await
        .map(|_ignored| ())
}


pub fn check_alert(alert: &Alert) -> Result<(), ApiFailure> {
    if valid_id(&alert.id) {
        Ok(())
    } else {
        Err(ApiFailure::Malformed("alert id"))
    }
}


pub fn check_page(page: &AlertPage) -> Result<(), ApiFailure> {
    if page.items.len() > MAX_ITEMS {
        Err(ApiFailure::Malformed("too many items"))
    } else if page.next_cursor.as_deref().is_some_and(|cursor| !valid_cursor(cursor)) {
        Err(ApiFailure::Malformed("cursor"))
    } else {
        page.items.iter().try_for_each(check_alert)
    }
}


pub fn alerts_path(cursor: Option<&str>, limit: Option<u32>) -> String {
    let mut query = Serializer::new(String::new());
    cursor.iter().for_each(|value| {
        query.append_pair("cursor", value);
    });
    limit.iter().for_each(|value| {
        query.append_pair("limit", &value.to_string());
    });
    format!("alerts?{}", query.finish())
}


pub async fn list_alerts(
    client: &ApiClient,
    source: IpAddr,
    token: &SecretString,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<AlertPage, ApiFailure> {
    let bytes = call(client, source, Method::GET, &alerts_path(cursor, limit), Some(token), None).await?;
    let page: AlertPage = serde_json::from_slice(&bytes)?;
    check_page(&page).map(|()| page)
}


/// An identifier that is not 64 lower-case hex digits is a missing alert without any call.
pub async fn get_alert(client: &ApiClient, source: IpAddr, token: &SecretString, id: &str) -> Result<Alert, ApiFailure> {
    if valid_id(id) {
        let bytes = call(client, source, Method::GET, &format!("alerts/{id}"), Some(token), None).await?;
        let alert: Alert = serde_json::from_slice(&bytes)?;
        if alert.id == id {
            Ok(alert)
        } else {
            Err(ApiFailure::Malformed("alert id differs"))
        }
    } else {
        Err(ApiFailure::NotFound)
    }
}


/// An asset id may become a link and an API path: 1 to 512 bytes, never a dot segment, in NFC, and it must render as itself (no unsafe character, no space twin, no right-to-left letter).
pub fn valid_asset_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ASSET_ID_BYTES
        && id != "."
        && id != ".."
        && id.chars().all(|character| !is_unsafe(character))
        && !id.starts_with(|character: char| character.is_ascii_whitespace())
        && !id.ends_with(|character: char| character.is_ascii_whitespace())
        && !id.contains("  ")
        && !id.split_once(':').is_some_and(|(_, value)| value.starts_with(' '))
        && id.split(' ').all(unchanged_by_clean_identity)
        && is_nfc(id)
        && displays_left_to_right(id)
}


/// In a left-to-right paragraph every level stays 0 unless a letter of bidi class R, AL or AN is present, which the display algorithm reorders.
pub fn displays_left_to_right(id: &str) -> bool {
    BidiInfo::new(id, Some(Level::ltr())).levels.iter().all(|level| *level == Level::ltr())
}


/// `clean_identity` cuts at `MAX_FIELD_CHARS`, so a space-free token is checked in chunks of that size.
pub fn unchanged_by_clean_identity(token: &str) -> bool {
    let characters: Vec<char> = token.chars().collect();
    characters.chunks(MAX_FIELD_CHARS).all(|chunk| {
        let piece: String = chunk.iter().collect();
        clean_identity(&piece) == piece
    })
}


/// The cursor of the CMDB: URL-safe base64 of an id, so up to 768 characters.
pub fn valid_asset_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= MAX_ASSET_CURSOR_CHARS
        && cursor
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_' || byte == b'=')
}


/// The id as one path segment: every byte outside ASCII alphanumerics and `*-._` is percent-encoded (the form encoder's `+` for a space is rewritten, a real `+` is `%2B`).
pub fn encode_asset_id(id: &str) -> String {
    byte_serialize(id.as_bytes()).collect::<String>().replace('+', "%20")
}


pub fn check_asset_page(page: &AssetPageView) -> Result<(), ApiFailure> {
    if page.items.len() > MAX_ITEMS {
        Err(ApiFailure::Malformed("too many items"))
    } else if page.next_cursor.as_deref().is_some_and(|cursor| !valid_asset_cursor(cursor)) {
        Err(ApiFailure::Malformed("cursor"))
    } else {
        Ok(())
    }
}


pub fn check_asset_detail(asset: &AssetDetailView, id: &str) -> Result<(), ApiFailure> {
    if asset.summary.id != id {
        Err(ApiFailure::Malformed("asset id differs"))
    } else if asset.keys.len() > MAX_ASSET_KEYS || asset.attributes.len() > MAX_ASSET_ATTRIBUTES {
        Err(ApiFailure::Malformed("too many entries"))
    } else {
        Ok(())
    }
}


pub fn assets_path(cursor: Option<&str>, limit: Option<u32>) -> String {
    let mut query = Serializer::new(String::new());
    cursor.iter().for_each(|value| {
        query.append_pair("cursor", value);
    });
    limit.iter().for_each(|value| {
        query.append_pair("limit", &value.to_string());
    });
    format!("assets?{}", query.finish())
}


pub async fn list_assets(
    client: &ApiClient,
    source: IpAddr,
    token: &SecretString,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<AssetPageView, ApiFailure> {
    let bytes = call(client, source, Method::GET, &assets_path(cursor, limit), Some(token), None).await?;
    let page: AssetPageView = serde_json::from_slice(&bytes)?;
    check_asset_page(&page).map(|()| page)
}


/// An identifier outside the asset grammar is a missing asset without any call; the path holds the encoded id only.
pub async fn get_asset(client: &ApiClient, source: IpAddr, token: &SecretString, id: &str) -> Result<AssetDetailView, ApiFailure> {
    if valid_asset_id(id) {
        let path = format!("assets/{}", encode_asset_id(id));
        let bytes = call(client, source, Method::GET, &path, Some(token), None).await?;
        let asset: AssetDetailView = serde_json::from_slice(&bytes)?;
        check_asset_detail(&asset, id).map(|()| asset)
    } else {
        Err(ApiFailure::NotFound)
    }
}


pub fn check_case_page(page: &CasePageView) -> Result<(), ApiFailure> {
    if page.items.len() > MAX_ITEMS {
        Err(ApiFailure::Malformed("too many items"))
    } else if page.next_cursor.as_deref().is_some_and(|cursor| !valid_cursor(cursor)) {
        Err(ApiFailure::Malformed("cursor"))
    } else {
        Ok(())
    }
}


pub fn cases_path(cursor: Option<&str>, limit: Option<u32>) -> String {
    let mut query = Serializer::new(String::new());
    cursor.iter().for_each(|value| {
        query.append_pair("cursor", value);
    });
    limit.iter().for_each(|value| {
        query.append_pair("limit", &value.to_string());
    });
    format!("cases?{}", query.finish())
}


pub async fn list_cases(
    client: &ApiClient,
    source: IpAddr,
    token: &SecretString,
    cursor: Option<&str>,
    limit: Option<u32>,
) -> Result<CasePageView, ApiFailure> {
    let bytes = call(client, source, Method::GET, &cases_path(cursor, limit), Some(token), None).await?;
    let page: CasePageView = serde_json::from_slice(&bytes)?;
    check_case_page(&page).map(|()| page)
}


/// An identifier outside the case grammar is a missing case without any call.
pub async fn get_case(client: &ApiClient, source: IpAddr, token: &SecretString, id: &str) -> Result<CaseDetailView, ApiFailure> {
    if valid_case_id(id) {
        let bytes = call(client, source, Method::GET, &format!("cases/{id}"), Some(token), None).await?;
        let case: CaseDetailView = serde_json::from_slice(&bytes)?;
        if case.summary.id == id {
            Ok(case)
        } else {
            Err(ApiFailure::Malformed("case id differs"))
        }
    } else {
        Err(ApiFailure::NotFound)
    }
}


/// `POST /cases/{id}/actions`: the id is checked first, the action and resolution come from the caller's fixed tables.
pub async fn post_case_action(
    client: &ApiClient,
    source: IpAddr,
    token: &SecretString,
    id: &str,
    action: &str,
    resolution: Option<&str>,
) -> Result<CaseDetailView, ApiFailure> {
    if valid_case_id(id) {
        let body = json!({ "action": action, "resolution": resolution }).to_string();
        let bytes = call(client, source, Method::POST, &format!("cases/{id}/actions"), Some(token), Some(body)).await?;
        let case: CaseDetailView = serde_json::from_slice(&bytes)?;
        if case.summary.id == id {
            Ok(case)
        } else {
            Err(ApiFailure::Malformed("case id differs"))
        }
    } else {
        Err(ApiFailure::NotFound)
    }
}


/// `POST /cases/{id}/comments`: the stored comment is the API's reply, never the submitted text.
pub async fn post_case_comment(client: &ApiClient, source: IpAddr, token: &SecretString, id: &str, text: &str) -> Result<CommentView, ApiFailure> {
    if valid_case_id(id) {
        let body = json!({ "text": text }).to_string();
        let bytes = call(client, source, Method::POST, &format!("cases/{id}/comments"), Some(token), Some(body)).await?;
        Ok(serde_json::from_slice(&bytes)?)
    } else {
        Err(ApiFailure::NotFound)
    }
}


/// The fixed spelling of an entity kind of the risk API, `None` for anything else.
pub fn risk_kind(text: &str) -> Option<&'static str> {
    RISK_KINDS.iter().find(|kind| **kind == text).copied()
}


pub fn risk_path(kind: Option<&str>) -> String {
    let mut query = Serializer::new(String::new());
    query.append_pair("limit", &RISK_LIMIT.to_string());
    kind.iter().for_each(|value| {
        query.append_pair("kind", value);
    });
    format!("risk/entities?{}", query.finish())
}


pub fn check_risk_list(list: &RiskListView) -> Result<(), ApiFailure> {
    if list.entities.len() > MAX_RISK_ENTITIES {
        Err(ApiFailure::Malformed("too many entities"))
    } else {
        Ok(())
    }
}


pub fn check_risk_detail(detail: &RiskDetailView, kind: &str, id: &str) -> Result<(), ApiFailure> {
    if detail.entity.kind != kind || detail.entity.id != id {
        Err(ApiFailure::Malformed("entity differs"))
    } else if detail.entity.value > MAX_RISK_VALUE {
        Err(ApiFailure::Malformed("score"))
    } else {
        Ok(())
    }
}


pub async fn list_risk(client: &ApiClient, source: IpAddr, token: &SecretString, kind: Option<&str>) -> Result<RiskListView, ApiFailure> {
    let bytes = call(client, source, Method::GET, &risk_path(kind), Some(token), None).await?;
    let list: RiskListView = serde_json::from_slice(&bytes)?;
    check_risk_list(&list).map(|()| list)
}


/// A kind outside `host` and `user` or an id outside the asset id grammar is a missing entity without any call; the path holds the encoded id only.
pub async fn get_risk_entity(client: &ApiClient, source: IpAddr, token: &SecretString, kind: &str, id: &str) -> Result<RiskDetailView, ApiFailure> {
    match risk_kind(kind).filter(|_| valid_asset_id(id)) {
        Some(fixed) => {
            let path = format!("risk/entities/{fixed}/{}", encode_asset_id(id));
            let bytes = call(client, source, Method::GET, &path, Some(token), None).await?;
            let detail: RiskDetailView = serde_json::from_slice(&bytes)?;
            check_risk_detail(&detail, fixed, id).map(|()| detail)
        }
        None => Err(ApiFailure::NotFound),
    }
}


/// The fixed spelling of a certificate filter, `None` for anything else.
pub fn cert_filter(text: &str) -> Option<&'static str> {
    CERT_FILTERS.iter().find(|filter| **filter == text).copied()
}


/// The certificate cursor of the API: a signed decimal time, `:` and a 64 character fingerprint, at most 85 characters.
pub fn valid_cert_cursor(cursor: &str) -> bool {
    cursor.len() <= MAX_CERT_CURSOR_CHARS
        && cursor.split_once(':').is_some_and(|(time, fingerprint)| {
            let digits = time.strip_prefix('-').unwrap_or(time);
            !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) && valid_id(fingerprint)
        })
}


/// `expiring_before` is computed by the caller from its clock and a fixed filter, never taken from the browser.
pub fn certs_path(cursor: Option<&str>, expiring_before: Option<i64>) -> String {
    let mut query = Serializer::new(String::new());
    query.append_pair("limit", &CERT_LIMIT.to_string());
    expiring_before.iter().for_each(|seconds| {
        query.append_pair("expiring_before", &seconds.to_string());
    });
    cursor.iter().for_each(|value| {
        query.append_pair("cursor", value);
    });
    format!("certificates?{}", query.finish())
}


pub fn check_cert_list(list: &CertListView) -> Result<(), ApiFailure> {
    if list.next_cursor.as_deref().is_some_and(|cursor| !valid_cert_cursor(cursor)) {
        Err(ApiFailure::Malformed("cursor"))
    } else {
        Ok(())
    }
}


pub fn check_cert_detail(detail: &CertDetailView, fingerprint: &str) -> Result<(), ApiFailure> {
    if detail.cert.fingerprint != fingerprint {
        Err(ApiFailure::Malformed("fingerprint differs"))
    } else {
        Ok(())
    }
}


pub const MAX_CERT_DNS_NAMES: usize = 1000;


#[derive(Deserialize)]
pub struct ListScan<'a> {
    #[serde(borrow)]
    pub items: Vec<&'a RawValue>,
}


#[derive(Deserialize)]
pub struct NamesScan<'a> {
    #[serde(borrow)]
    pub dns_names: Vec<&'a RawValue>,
}


#[derive(Deserialize)]
pub struct DetailScan<'a> {
    #[serde(borrow)]
    pub dns_names: Vec<&'a RawValue>,
    #[serde(borrow)]
    pub sightings: Vec<&'a RawValue>,
}


/// Counts items and DNS names on raw slices, before any typed value is built.
pub fn scan_cert_list(bytes: &[u8]) -> Result<(), ApiFailure> {
    let scan: ListScan = serde_json::from_slice(bytes)?;
    if scan.items.len() > MAX_ITEMS {
        Err(ApiFailure::Malformed("too many items"))
    } else {
        scan.items.iter().try_for_each(|item| {
            let names: NamesScan = serde_json::from_str(item.get())?;
            if names.dns_names.len() > MAX_CERT_DNS_NAMES {
                Err(ApiFailure::Malformed("too many DNS names"))
            } else {
                Ok(())
            }
        })
    }
}


pub fn scan_cert_detail(bytes: &[u8]) -> Result<(), ApiFailure> {
    let scan: DetailScan = serde_json::from_slice(bytes)?;
    if scan.dns_names.len() > MAX_CERT_DNS_NAMES {
        Err(ApiFailure::Malformed("too many DNS names"))
    } else if scan.sightings.len() > MAX_CERT_SIGHTINGS {
        Err(ApiFailure::Malformed("too many sightings"))
    } else {
        Ok(())
    }
}


pub async fn list_certs(
    client: &ApiClient,
    source: IpAddr,
    token: &SecretString,
    cursor: Option<&str>,
    expiring_before: Option<i64>,
) -> Result<CertListView, ApiFailure> {
    let bytes = call(client, source, Method::GET, &certs_path(cursor, expiring_before), Some(token), None).await?;
    scan_cert_list(&bytes)?;
    let list: CertListView = serde_json::from_slice(&bytes)?;
    check_cert_list(&list).map(|()| list)
}


/// A fingerprint that is not 64 lower-case hex digits is a missing certificate without any call.
pub async fn get_cert(client: &ApiClient, source: IpAddr, token: &SecretString, fingerprint: &str) -> Result<CertDetailView, ApiFailure> {
    if valid_id(fingerprint) {
        let bytes = call(client, source, Method::GET, &format!("certificates/{fingerprint}"), Some(token), None).await?;
        scan_cert_detail(&bytes)?;
        let detail: CertDetailView = serde_json::from_slice(&bytes)?;
        check_cert_detail(&detail, fingerprint).map(|()| detail)
    } else {
        Err(ApiFailure::NotFound)
    }
}


pub const HUNT_LIMIT: u32 = 100;


pub const MAX_HUNT_CURSOR_CHARS: usize = 114;


pub const MAX_PACK_ID_CHARS: usize = 64;


/// The hunt cursor of the API: unpadded base64url, at most 114 characters.
pub fn valid_hunt_cursor(cursor: &str) -> bool {
    !cursor.is_empty() && cursor.len() <= MAX_HUNT_CURSOR_CHARS && BASE64URL_NOPAD.decode(cursor.as_bytes()).is_ok()
}


/// The pack id grammar of the hunt-packs module: `[a-z0-9][a-z0-9_.-]{0,63}`.
pub fn valid_pack_id(id: &str) -> bool {
    let mut characters = id.chars();
    id.len() <= MAX_PACK_ID_CHARS
        && characters
            .next()
            .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && characters.all(|next| next.is_ascii_lowercase() || next.is_ascii_digit() || matches!(next, '_' | '.' | '-'))
}


pub fn hunts_path(cursor: Option<&str>) -> String {
    let mut query = Serializer::new(String::new());
    query.append_pair("limit", &HUNT_LIMIT.to_string());
    cursor.iter().for_each(|value| {
        query.append_pair("cursor", value);
    });
    format!("hunts/findings?{}", query.finish())
}


pub fn check_hunt_list(list: &FindingsView) -> Result<(), ApiFailure> {
    if list.next_cursor.as_deref().is_some_and(|cursor| !valid_hunt_cursor(cursor)) {
        Err(ApiFailure::Malformed("cursor"))
    } else {
        Ok(())
    }
}


/// Counts the items on raw slices, at most the limit that was sent, before any typed value is built.
pub fn scan_hunt_list(bytes: &[u8]) -> Result<(), ApiFailure> {
    let scan: ListScan = serde_json::from_slice(bytes)?;
    if scan.items.len() > HUNT_LIMIT as usize {
        Err(ApiFailure::Malformed("too many items"))
    } else {
        Ok(())
    }
}


pub async fn list_findings(client: &ApiClient, source: IpAddr, token: &SecretString, cursor: Option<&str>) -> Result<FindingsView, ApiFailure> {
    let bytes = call(client, source, Method::GET, &hunts_path(cursor), Some(token), None).await?;
    scan_hunt_list(&bytes)?;
    let list: FindingsView = serde_json::from_slice(&bytes)?;
    check_hunt_list(&list).map(|()| list)
}
