use crate::error::ApiFailure;
use crate::model::{Alert, AlertPage, ApiClient, CaseDetailView, CasePageView};
use reqwest::header::{HeaderName, HeaderValue, CONTENT_TYPE};
use reqwest::{Method, Response, StatusCode};
use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;
use serde_json::json;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::{timeout_at, Instant};
use url::form_urlencoded::Serializer;


pub const MAX_BODY_BYTES: usize = 1_048_576;


pub const MAX_BODY_READS: usize = 4096;


pub const MAX_ITEMS: usize = 100;


pub const MAX_TOKEN_BYTES: usize = 4096;


pub const MAX_CURSOR_CHARS: usize = 512;


pub const ID_LENGTH: usize = 64;


pub const MAX_CASE_ID_CHARS: usize = 128;


pub const FORWARDED: HeaderName = HeaderName::from_static("forwarded");


pub const JSON_TYPE: HeaderValue = HeaderValue::from_static("application/json");


#[derive(Debug, Deserialize)]
pub struct TokenReply {
    pub token: String,
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
        let chunk = response.chunk().await.map_err(ApiFailure::Unavailable)?;
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
    let response = request.send().await.map_err(ApiFailure::Unavailable)?;
    classify(response.status())?;
    read_capped(response).await
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
