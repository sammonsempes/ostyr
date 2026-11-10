use crate::alert::{Alert, Event};
use crate::error::LinkError;
use crate::limits::{
    LINK_ACTION_ACKNOWLEDGE, LINK_ACTION_RESOLVE, LINK_LIFETIME_SECONDS, LINK_SKEW_SECONDS, MAC_BYTES, MAX_TOKEN_CHARS, NONCE_BYTES,
};
use crate::store::apply_event;
use crate::types::{FillFn, IssueError, LinkKey, Row};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};
use core_pg::scope::{tenant_scope, TenantScope};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::future::Future;


pub const DOMAIN_SEPARATOR: &[u8] = b"ostyr-oncall-ack-link-v1";


pub const ALERT_BYTES: usize = 8;


pub const EXPIRY_BYTES: usize = 8;


#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkAction {
    Acknowledge,
    Resolve,
}


#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Nonce(pub [u8; NONCE_BYTES]);


/// What a token says; `expires_at` is in Unix seconds and the link is valid up to and including it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claims {
    pub tenant: String,
    pub alert: i64,
    pub action: LinkAction,
    pub expires_at: i64,
    pub nonce: Nonce,
}


pub fn os_random(buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    getrandom::fill(buffer)
}


pub fn action_byte(action: LinkAction) -> u8 {
    match action {
        LinkAction::Acknowledge => LINK_ACTION_ACKNOWLEDGE,
        LinkAction::Resolve => LINK_ACTION_RESOLVE,
    }
}


pub fn action_from_byte(byte: u8) -> Option<LinkAction> {
    match byte {
        LINK_ACTION_ACKNOWLEDGE => Some(LinkAction::Acknowledge),
        LINK_ACTION_RESOLVE => Some(LinkAction::Resolve),
        _ => None,
    }
}


pub fn event_of(action: LinkAction) -> Event {
    match action {
        LinkAction::Acknowledge => Event::Acknowledge,
        LinkAction::Resolve => Event::Resolve,
    }
}


/// Tenant length, tenant, alert, action, expiry, nonce.
pub fn payload_bytes(claims: &Claims) -> Vec<u8> {
    let tenant = claims.tenant.as_bytes();
    let mut payload = Vec::new();
    payload.push(u8::try_from(tenant.len()).unwrap_or(u8::MAX));
    payload.extend_from_slice(tenant);
    payload.extend_from_slice(&claims.alert.to_be_bytes());
    payload.push(action_byte(claims.action));
    payload.extend_from_slice(&claims.expires_at.to_be_bytes());
    payload.extend_from_slice(&claims.nonce.0);
    payload
}


/// The key is hashed to a fixed-size block first, so building the MAC cannot fail on a key length.
pub fn mac_over(key: &LinkKey, payload: &[u8]) -> Hmac<Sha256> {
    let digest = Sha256::digest(key.0.as_slice());
    let mut block = hmac::digest::Key::<Hmac<Sha256>>::default();
    block.iter_mut().zip(digest.iter()).for_each(|(target, source)| *target = *source);
    let mut mac = <Hmac<Sha256> as Mac>::new(&block);
    mac.update(DOMAIN_SEPARATOR);
    mac.update(payload);
    mac
}


/// The opaque token: URL-safe base64 of the payload followed by its HMAC-SHA256.
pub fn seal(claims: &Claims, key: &LinkKey) -> String {
    let mut bytes = payload_bytes(claims);
    let tag = mac_over(key, &bytes).finalize().into_bytes();
    bytes.extend_from_slice(&tag);
    URL_SAFE_NO_PAD.encode(bytes)
}


pub fn issue_link_with(alert: i64, action: LinkAction, tenant: &str, now: DateTime<Utc>, key: &LinkKey, fill: FillFn) -> Result<String, IssueError> {
    tenant_scope(tenant).map_err(|_refused| LinkError::InvalidTenant)?;
    let mut nonce = [0; NONCE_BYTES];
    fill(&mut nonce).map_err(LinkError::Random)?;
    let claims = Claims {
        tenant: tenant.to_owned(),
        alert,
        action,
        expires_at: now.timestamp().saturating_add(LINK_LIFETIME_SECONDS),
        nonce: Nonce(nonce),
    };
    Ok(seal(&claims, key))
}


/// A signed, single-use link for `action` on `alert`, valid for `LINK_LIFETIME_SECONDS`.
pub fn issue_link(alert: i64, action: LinkAction, tenant: &str, now: DateTime<Utc>, key: &LinkKey) -> Result<String, IssueError> {
    issue_link_with(alert, action, tenant, now, key, os_random)
}


/// Reads the claims of an authentic payload; `None` when the structure is wrong.
pub fn parse_claims(payload: &[u8]) -> Option<Claims> {
    let (tenant_len, after_len) = payload.split_first()?;
    let (tenant, tail) = after_len.split_at_checked(usize::from(*tenant_len))?;
    let (alert, after_alert) = tail.split_at_checked(ALERT_BYTES)?;
    let (action, after_action) = after_alert.split_first()?;
    let (expiry, nonce) = after_action.split_at_checked(EXPIRY_BYTES)?;
    Some(Claims {
        tenant: String::from_utf8(tenant.to_vec()).ok()?,
        alert: i64::from_be_bytes(alert.try_into().ok()?),
        action: action_from_byte(*action)?,
        expires_at: i64::from_be_bytes(expiry.try_into().ok()?),
        nonce: Nonce(nonce.try_into().ok()?),
    })
}


/// Length and encoding first, then the MAC in constant time, then the structure and the expiry. Records nothing.
pub fn verify_link<UsedError: std::error::Error + 'static>(token: &str, now: DateTime<Utc>, key: &LinkKey) -> Result<Claims, LinkError<UsedError>> {
    if token.is_empty() || token.len() > MAX_TOKEN_CHARS {
        Err(LinkError::Malformed)
    } else {
        let bytes = URL_SAFE_NO_PAD.decode(token).map_err(|_refused| LinkError::Malformed)?;
        let split = bytes.len().checked_sub(MAC_BYTES).ok_or(LinkError::Malformed)?;
        let (payload, tag) = bytes.split_at_checked(split).ok_or(LinkError::Malformed)?;
        mac_over(key, payload).verify_slice(tag).map_err(|_refused| LinkError::Tampered)?;
        let claims = parse_claims(payload).ok_or(LinkError::Malformed)?;
        let seconds = now.timestamp();
        if claims.expires_at < seconds {
            Err(LinkError::Expired)
        } else if claims.expires_at > seconds.saturating_add(LINK_LIFETIME_SECONDS + LINK_SKEW_SECONDS) {
            Err(LinkError::Malformed)
        } else {
            Ok(claims)
        }
    }
}


/// Records the nonce through the injected store: `true` means newly recorded, `false` a replay.
pub fn record_use<UsedError, Used>(claims: &Claims, used: &mut Used) -> Result<(), LinkError<UsedError>>
where
    UsedError: std::error::Error + 'static,
    Used: FnMut(&Nonce) -> Result<bool, UsedError>,
{
    if used(&claims.nonce).map_err(LinkError::Used)? {
        Ok(())
    } else {
        Err(LinkError::Reused)
    }
}


pub fn redeem_link<UsedError, Used>(token: &str, now: DateTime<Utc>, key: &LinkKey, used: &mut Used) -> Result<Claims, LinkError<UsedError>>
where
    UsedError: std::error::Error + 'static,
    Used: FnMut(&Nonce) -> Result<bool, UsedError>,
{
    let claims = verify_link(token, now, key)?;
    record_use(&claims, used)?;
    Ok(claims)
}


/// Applies the event in the token tenant; another tenant is refused before the nonce is recorded, a later store failure burns the link.
pub async fn apply_link<Executor, Pending, UsedError, Used>(
    exec: &mut Executor,
    tenant: &str,
    token: &str,
    now: DateTime<Utc>,
    key: &LinkKey,
    used: &mut Used,
) -> Result<Alert, LinkError<UsedError>>
where
    Executor: FnMut(&TenantScope, crate::alert::Statement) -> Pending,
    Pending: Future<Output = Result<Vec<Row>, crate::error::StoreError>>,
    UsedError: std::error::Error + 'static,
    Used: FnMut(&Nonce) -> Result<bool, UsedError>,
{
    let claims = verify_link(token, now, key)?;
    if claims.tenant == tenant {
        let scope = tenant_scope(&claims.tenant).map_err(|_refused| LinkError::InvalidTenant)?;
        record_use(&claims, used)?;
        apply_event(exec, &scope, claims.alert, event_of(claims.action), now)
            .await
            .map_err(LinkError::Alert)
    } else {
        Err(LinkError::OtherTenant)
    }
}
