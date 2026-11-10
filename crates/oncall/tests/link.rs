#[path = "common/types.rs"]
mod types;


use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, TimeZone, Utc};
use core_pg::scope::{tenant_of, TenantScope, MAX_TENANT_BYTES};
use hmac::Mac;
use oncall::alert::{Cell, Param, Phase, Statement};
use oncall::error::{LinkError, StoreError};
use oncall::limits::{LINK_LIFETIME_SECONDS, LINK_SKEW_SECONDS, MAC_BYTES, MAX_TOKEN_CHARS, NONCE_BYTES};
use oncall::link::{
    action_byte, action_from_byte, apply_link, issue_link, issue_link_with, mac_over, parse_claims, payload_bytes, redeem_link, seal, verify_link,
    Claims, LinkAction, Nonce, ALERT_BYTES, EXPIRY_BYTES,
};
use oncall::rows::phase_name;
use oncall::store::{GET_SQL, UPDATE_SQL};
use oncall::types::Row;
use std::cell::RefCell;
use std::collections::HashSet;
use std::error::Error;
use std::future::{ready, Ready};
use std::io;
use std::rc::Rc;
use types::TestResult;


const STAMP: i64 = 1_700_000_000;


const KEY: &[u8] = b"0123456789abcdef0123456789abcdef";


const OTHER_KEY: &[u8] = b"fedcba9876543210fedcba9876543210";


const ALERT: i64 = 7;


const TWO_LINKS: usize = 2;


const LATER: i64 = 2;


fn at(offset: i64) -> Result<DateTime<Utc>, Box<dyn Error>> {
    Ok(Utc.timestamp_opt(STAMP + offset, 0).single().ok_or("bad stamp")?)
}


fn used_store() -> Rc<RefCell<HashSet<Nonce>>> {
    Rc::new(RefCell::new(HashSet::new()))
}


fn used_fn(set: &Rc<RefCell<HashSet<Nonce>>>) -> impl FnMut(&Nonce) -> Result<bool, io::Error> {
    let shared = Rc::clone(set);
    move |nonce: &Nonce| Ok(shared.borrow_mut().insert(*nonce))
}


fn failing_used(_nonce: &Nonce) -> Result<bool, io::Error> {
    Err(io::Error::other("store down"))
}


fn failing_fill(_buffer: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}


fn token(action: LinkAction, tenant: &str) -> Result<String, Box<dyn Error>> {
    Ok(issue_link(ALERT, action, tenant, at(0)?, KEY)?)
}


fn rebuilt(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}


fn with_mac(payload: &[u8]) -> Result<String, Box<dyn Error>> {
    let tag = mac_over(KEY, payload)?.finalize().into_bytes();
    let mut bytes = payload.to_vec();
    bytes.extend_from_slice(&tag);
    Ok(rebuilt(&bytes))
}


fn verified(token: &str, offset: i64) -> Result<Result<Claims, LinkError<io::Error>>, Box<dyn Error>> {
    Ok(verify_link(token, at(offset)?, KEY))
}


#[test]
fn a_link_round_trips() -> TestResult {
    let set = used_store();
    let claims = redeem_link(&token(LinkAction::Resolve, "acme")?, at(1)?, KEY, &mut used_fn(&set))?;
    assert_eq!(
        (claims.tenant.as_str(), claims.alert, claims.action),
        ("acme", ALERT, LinkAction::Resolve)
    );
    assert_eq!(claims.expires_at, STAMP + LINK_LIFETIME_SECONDS);
    assert_eq!(set.borrow().len(), 1);
    let again = redeem_link(&token(LinkAction::Acknowledge, "acme")?, at(1)?, KEY, &mut used_fn(&set))?;
    assert_eq!(again.action, LinkAction::Acknowledge);
    assert_eq!(set.borrow().len(), TWO_LINKS);
    Ok(())
}


#[test]
fn every_byte_field_of_the_token_is_covered_by_the_mac() -> TestResult {
    let genuine = token(LinkAction::Acknowledge, "acme")?;
    let bytes = URL_SAFE_NO_PAD.decode(&genuine)?;
    let tenant_at = 1;
    let alert_at = tenant_at + "acme".len();
    let action_at = alert_at + ALERT_BYTES;
    let expiry_at = action_at + 1;
    let nonce_at = expiry_at + EXPIRY_BYTES;
    let mac_at = nonce_at + NONCE_BYTES;
    assert_eq!(bytes.len(), mac_at + MAC_BYTES);
    for position in [0, tenant_at, alert_at, action_at, expiry_at, nonce_at, mac_at, bytes.len() - 1] {
        let mut flipped = bytes.clone();
        *flipped.get_mut(position).ok_or("position")? ^= 1;
        assert!(
            matches!(verified(&rebuilt(&flipped), 1)?, Err(LinkError::Tampered)),
            "position {position}"
        );
    }
    assert!(matches!(verify_link::<io::Error>(&genuine, at(1)?, OTHER_KEY), Err(LinkError::Tampered)));
    Ok(())
}


#[test]
fn the_expiry_is_inclusive_and_one_second_later_refuses() -> TestResult {
    let genuine = token(LinkAction::Acknowledge, "acme")?;
    assert!(verified(&genuine, LINK_LIFETIME_SECONDS)?.is_ok());
    assert!(matches!(verified(&genuine, LINK_LIFETIME_SECONDS + 1)?, Err(LinkError::Expired)));
    let set = used_store();
    let late = redeem_link(&genuine, at(LINK_LIFETIME_SECONDS + 1)?, KEY, &mut used_fn(&set));
    assert!(matches!(late, Err(LinkError::Expired)) && set.borrow().is_empty());
    Ok(())
}


#[test]
fn a_lifetime_beyond_the_bound_is_refused() -> TestResult {
    let claims = |offset: i64| Claims {
        tenant: "acme".to_owned(),
        alert: ALERT,
        action: LinkAction::Resolve,
        expires_at: STAMP + LINK_LIFETIME_SECONDS + offset,
        nonce: Nonce([0; NONCE_BYTES]),
    };
    assert!(verified(&seal(&claims(LINK_SKEW_SECONDS), KEY)?, 0)?.is_ok());
    assert!(matches!(
        verified(&seal(&claims(LINK_SKEW_SECONDS + 1), KEY)?, 0)?,
        Err(LinkError::Malformed)
    ));
    Ok(())
}


#[test]
fn a_reused_link_is_refused() -> TestResult {
    let genuine = token(LinkAction::Resolve, "acme")?;
    let set = used_store();
    redeem_link(&genuine, at(1)?, KEY, &mut used_fn(&set))?;
    assert!(matches!(
        redeem_link(&genuine, at(LATER)?, KEY, &mut used_fn(&set)),
        Err(LinkError::Reused)
    ));
    assert_eq!(LinkError::<io::Error>::Reused.to_string(), "the link was already used");
    Ok(())
}


#[test]
fn a_failing_used_store_is_a_typed_error() -> TestResult {
    let genuine = token(LinkAction::Resolve, "acme")?;
    let refused = redeem_link(&genuine, at(1)?, KEY, &mut failing_used);
    assert!(matches!(refused, Err(LinkError::Used(_))));
    assert!(refused.err().and_then(|error| error.source().map(ToString::to_string)) == Some("store down".to_owned()));
    Ok(())
}


#[test]
fn malformed_and_oversized_tokens_are_refused_before_any_mac_or_store_work() -> TestResult {
    let calls = Rc::new(RefCell::new(Vec::<Nonce>::new()));
    let counter = Rc::clone(&calls);
    let mut counting = move |_nonce: &Nonce| -> Result<bool, io::Error> {
        counter.borrow_mut().push(Nonce([0; NONCE_BYTES]));
        Ok(true)
    };
    let genuine = token(LinkAction::Resolve, "acme")?;
    let oversized = "A".repeat(MAX_TOKEN_CHARS + 1);
    let padded = format!("{genuine}=");
    let short = rebuilt(&[0; MAC_BYTES - 1]);
    for bad in ["", "!!!!", "not base64 at all", oversized.as_str(), padded.as_str(), short.as_str()] {
        assert!(matches!(redeem_link(bad, at(1)?, KEY, &mut counting), Err(LinkError::Malformed)), "{bad}");
    }
    assert!(calls.borrow().is_empty());
    let longest = issue_link(ALERT, LinkAction::Resolve, &"a".repeat(MAX_TENANT_BYTES), at(0)?, KEY)?;
    assert!(longest.len() <= MAX_TOKEN_CHARS);
    Ok(())
}


#[test]
fn an_authentic_payload_with_a_wrong_structure_is_malformed() -> TestResult {
    let claims = Claims {
        tenant: "acme".to_owned(),
        alert: ALERT,
        action: LinkAction::Resolve,
        expires_at: STAMP + 1,
        nonce: Nonce([0; NONCE_BYTES]),
    };
    let genuine = payload_bytes(&claims);
    let mut bad_action = genuine.clone();
    *bad_action.get_mut(1 + "acme".len() + ALERT_BYTES).ok_or("action")? = u8::MAX;
    let mut bad_utf8 = genuine.clone();
    *bad_utf8.get_mut(1).ok_or("tenant")? = u8::MAX;
    let mut long_declared = genuine.clone();
    *long_declared.first_mut().ok_or("length")? = u8::MAX;
    let mut trailing = genuine.clone();
    trailing.push(0);
    for payload in [
        vec![],
        vec![0],
        bad_action,
        bad_utf8,
        long_declared,
        trailing,
        genuine.get(..genuine.len() - 1).ok_or("cut")?.to_vec(),
    ] {
        assert!(matches!(verified(&with_mac(&payload)?, 0)?, Err(LinkError::Malformed)), "{payload:?}");
    }
    assert_eq!(parse_claims(&genuine), Some(claims));
    Ok(())
}


#[test]
fn the_action_bytes_round_trip_and_the_unknown_one_is_refused() -> TestResult {
    for action in [LinkAction::Acknowledge, LinkAction::Resolve] {
        assert_eq!(action_from_byte(action_byte(action)), Some(action));
    }
    assert_eq!(action_from_byte(0), None);
    Ok(())
}


#[test]
fn the_tenant_is_validated_and_the_random_source_may_fail() -> TestResult {
    let too_long = "a".repeat(MAX_TENANT_BYTES + 1);
    for bad in ["", "has space", too_long.as_str(), "-x"] {
        assert!(
            matches!(issue_link(ALERT, LinkAction::Resolve, bad, at(0)?, KEY), Err(LinkError::InvalidTenant)),
            "{bad}"
        );
    }
    let failed = issue_link_with(ALERT, LinkAction::Resolve, "acme", at(0)?, KEY, failing_fill);
    assert!(matches!(failed, Err(LinkError::Random(_))));
    let first = token(LinkAction::Resolve, "acme")?;
    assert_ne!(first, token(LinkAction::Resolve, "acme")?);
    Ok(())
}


#[test]
fn errors_carry_fixed_texts_and_no_key_material() -> TestResult {
    let texts = [
        LinkError::<io::Error>::Malformed,
        LinkError::Tampered,
        LinkError::Expired,
        LinkError::Reused,
        LinkError::OtherTenant,
        LinkError::InvalidTenant,
    ]
    .map(|error| format!("{error} {error:?}"));
    let key_text = String::from_utf8(KEY.to_vec())?;
    assert!(texts.iter().all(|text| !text.contains(&key_text)));
    let genuine = token(LinkAction::Resolve, "acme")?;
    let flipped = genuine.replacen(genuine.get(..1).ok_or("first")?, if genuine.starts_with('A') { "B" } else { "A" }, 1);
    let message = format!("{:?}", verify_link::<io::Error>(&flipped, at(0)?, KEY).err());
    assert!(!message.contains(&genuine) && !message.contains(&flipped));
    Ok(())
}


struct World {
    alerts: Vec<(String, i64, String)>,
}


fn row(id: i64, phase: &str) -> Row {
    let none = Cell::Time(None);
    vec![
        Cell::Int(id),
        Cell::Text("fp".to_owned()),
        Cell::Text(phase.to_owned()),
        Cell::Int(0),
        Cell::Int(1),
        Cell::Int(1),
        Cell::Time(Utc.timestamp_opt(STAMP, 0).single()),
        none.clone(),
        none,
    ]
}


fn handle(world: &Rc<RefCell<World>>, scope: &TenantScope, statement: &Statement) -> Result<Vec<Row>, StoreError> {
    let id = match statement.params.first() {
        Some(Param::Int(value)) => *value,
        _ => i64::MIN,
    };
    let mut state = world.borrow_mut();
    let found = state
        .alerts
        .iter_mut()
        .find(|(tenant, alert, _)| tenant == tenant_of(scope) && *alert == id);
    Ok(match (statement.sql, found) {
        (GET_SQL, Some((_, _, phase))) => vec![row(id, phase)],
        (UPDATE_SQL, Some((_, _, phase))) => match statement.params.get(1) {
            Some(Param::Text(next)) => {
                *phase = next.clone();
                vec![row(id, phase)]
            }
            _ => vec![],
        },
        _ => vec![],
    })
}


fn world() -> Rc<RefCell<World>> {
    Rc::new(RefCell::new(World {
        alerts: vec![
            ("acme".to_owned(), ALERT, "open".to_owned()),
            ("other".to_owned(), ALERT, "open".to_owned()),
        ],
    }))
}


fn phase_of(world: &Rc<RefCell<World>>, tenant: &str) -> Option<String> {
    world
        .borrow()
        .alerts
        .iter()
        .find(|(owner, _, _)| owner == tenant)
        .map(|(_, _, phase)| phase.clone())
}


fn exec_for(world: &Rc<RefCell<World>>) -> impl FnMut(&TenantScope, Statement) -> Ready<Result<Vec<Row>, StoreError>> {
    let shared = Rc::clone(world);
    move |scope: &TenantScope, statement: Statement| ready(handle(&shared, scope, &statement))
}


#[tokio::test]
async fn a_redeemed_link_acts_in_its_own_tenant_only() -> TestResult {
    let state = world();
    let mut exec = exec_for(&state);
    let set = used_store();
    let alert = apply_link(
        &mut exec,
        "acme",
        &token(LinkAction::Acknowledge, "acme")?,
        at(1)?,
        KEY,
        &mut used_fn(&set),
    )
    .await?;
    assert_eq!(alert.state.phase, Phase::Acknowledged);
    assert_eq!(phase_of(&state, "acme").as_deref(), Some(phase_name(Phase::Acknowledged)));
    assert_eq!(phase_of(&state, "other").as_deref(), Some(phase_name(Phase::Open)));
    Ok(())
}


#[tokio::test]
async fn a_token_of_another_tenant_is_refused_and_not_consumed() -> TestResult {
    let state = world();
    let mut exec = exec_for(&state);
    let set = used_store();
    let foreign = token(LinkAction::Resolve, "other")?;
    let refused = apply_link(&mut exec, "acme", &foreign, at(1)?, KEY, &mut used_fn(&set)).await;
    assert!(matches!(refused, Err(LinkError::OtherTenant)));
    assert!(set.borrow().is_empty());
    assert_eq!(phase_of(&state, "other").as_deref(), Some("open"));
    Ok(())
}


#[tokio::test]
async fn a_link_for_an_alert_of_nobody_is_not_found_and_a_replay_is_refused() -> TestResult {
    let state = world();
    let mut exec = exec_for(&state);
    let set = used_store();
    let missing = issue_link(ALERT + 1, LinkAction::Resolve, "acme", at(0)?, KEY)?;
    let refused = apply_link(&mut exec, "acme", &missing, at(1)?, KEY, &mut used_fn(&set)).await;
    assert!(matches!(refused, Err(LinkError::Alert(StoreError::NotFound))));
    let resolve = token(LinkAction::Resolve, "acme")?;
    apply_link(&mut exec, "acme", &resolve, at(1)?, KEY, &mut used_fn(&set)).await?;
    let replay = apply_link(&mut exec, "acme", &resolve, at(LATER)?, KEY, &mut used_fn(&set)).await;
    assert!(matches!(replay, Err(LinkError::Reused)));
    let forged = apply_link(&mut exec, "acme", "!!", at(LATER)?, KEY, &mut used_fn(&set)).await;
    assert!(matches!(forged, Err(LinkError::Malformed)));
    Ok(())
}


#[tokio::test]
async fn a_token_with_an_invalid_tenant_name_is_refused_even_when_authentic() -> TestResult {
    let state = world();
    let mut exec = exec_for(&state);
    let set = used_store();
    let claims = Claims {
        tenant: "bad tenant".to_owned(),
        alert: ALERT,
        action: LinkAction::Resolve,
        expires_at: STAMP + 1,
        nonce: Nonce([1; NONCE_BYTES]),
    };
    let refused = apply_link(&mut exec, "bad tenant", &seal(&claims, KEY)?, at(0)?, KEY, &mut used_fn(&set)).await;
    assert!(matches!(refused, Err(LinkError::InvalidTenant)));
    Ok(())
}
