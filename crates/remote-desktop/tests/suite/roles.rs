use crate::common::types::TestResult;
use crate::common::{claims, setup, signing_key, token_for, token_unchecked, KEY_ID, NOW, PEER, RELAY_SEED, TENANT};
use data_encoding::BASE64URL_NOPAD;
use remote_desktop::error::{ClaimError, IssueError, TokenError};
use remote_desktop::model::{ConnType, Envelope, RelayClaims, Role, NONCE_LENGTH, SESSION_ID_LENGTH};
use remote_desktop::sign::memory_signer;
use remote_desktop::token::{check_role, check_token, issue_token, seal};
use serde::Serialize;
use std::error::Error;


const MARKER_SUBJECT: &str = "zq7marker-subject";


const UNKNOWN_VARIANT: u8 = 9;


const SECOND: u8 = 2;


#[derive(Serialize)]
struct RawClaims {
    key_id: String,
    role: u8,
    conn_type: u8,
    tenant: String,
    session_id: [u8; SESSION_ID_LENGTH],
    device_peer_id: String,
    viewer_subject: String,
    not_before: u64,
    expires_at: u64,
    nonce: [u8; NONCE_LENGTH],
}


#[derive(Serialize)]
struct RolelessClaims {
    key_id: String,
    tenant: String,
    session_id: [u8; SESSION_ID_LENGTH],
    device_peer_id: String,
    viewer_subject: String,
    not_before: u64,
    expires_at: u64,
    nonce: [u8; NONCE_LENGTH],
}


fn device_claims(nonce: u8) -> RelayClaims {
    let mut device = claims(nonce);
    device.role = Role::Device;
    device.viewer_subject = String::new();
    device
}


fn raw(role: u8, conn_type: u8) -> RawClaims {
    let base = claims(1);
    RawClaims {
        key_id: base.key_id,
        role,
        conn_type,
        tenant: base.tenant,
        session_id: base.session_id,
        device_peer_id: base.device_peer_id,
        viewer_subject: base.viewer_subject,
        not_before: base.not_before,
        expires_at: base.expires_at,
        nonce: base.nonce,
    }
}


fn sealed(bytes: Vec<u8>) -> Result<String, Box<dyn Error>> {
    Ok(seal(&memory_signer(signing_key(RELAY_SEED)), KEY_ID, bytes)?)
}


fn refusal(token: &str, role: Role) -> Result<TokenError, Box<dyn Error>> {
    let setup = setup()?;
    check_token(&setup.verifier, token, role, PEER, TENANT, NOW)
        .err()
        .ok_or_else(|| "accepted".into())
}


#[test]
fn each_role_is_accepted_only_as_itself_and_a_refusal_burns_nothing() -> TestResult {
    let setup = setup()?;
    let viewer = token_for(&claims(1))?;
    let device = token_for(&device_claims(SECOND))?;
    assert!(matches!(
        check_token(&setup.verifier, &viewer, Role::Device, PEER, TENANT, NOW),
        Err(TokenError::WrongRole)
    ));
    assert!(matches!(
        check_token(&setup.verifier, &device, Role::Viewer, PEER, TENANT, NOW),
        Err(TokenError::WrongRole)
    ));
    assert_eq!(check_token(&setup.verifier, &viewer, Role::Viewer, PEER, TENANT, NOW)?.role, Role::Viewer);
    let accepted = check_token(&setup.verifier, &device, Role::Device, PEER, TENANT, NOW)?;
    assert_eq!(
        (accepted.role, accepted.conn_type, accepted.viewer_subject.as_str()),
        (Role::Device, ConnType::DefaultConn, "")
    );
    assert!(check_role(&accepted, Role::Device).is_ok());
    assert!(matches!(check_role(&accepted, Role::Viewer), Err(TokenError::WrongRole)));
    Ok(())
}


#[test]
fn a_device_token_with_a_subject_is_refused_at_issue_and_at_verify() -> TestResult {
    let mut hostile = device_claims(1);
    hostile.viewer_subject = "alice".to_owned();
    let signer = memory_signer(signing_key(RELAY_SEED));
    assert!(matches!(
        issue_token(&signer, &hostile),
        Err(IssueError::Claims(ClaimError::DeviceSubject))
    ));
    assert!(matches!(
        refusal(&token_unchecked(&hostile)?, Role::Device)?,
        TokenError::Claims(ClaimError::DeviceSubject)
    ));
    let mut empty_viewer = claims(1);
    empty_viewer.viewer_subject = String::new();
    assert!(matches!(
        refusal(&token_unchecked(&empty_viewer)?, Role::Viewer)?,
        TokenError::Claims(ClaimError::Subject)
    ));
    Ok(())
}


#[test]
fn a_role_or_conn_type_outside_the_enum_is_malformed() -> TestResult {
    let unknown_role = refusal(&sealed(postcard::to_stdvec(&raw(UNKNOWN_VARIANT, 0))?)?, Role::Viewer)?;
    assert!(matches!(unknown_role, TokenError::Malformed(_)));
    let unknown_type = refusal(&sealed(postcard::to_stdvec(&raw(0, 1))?)?, Role::Viewer)?;
    assert!(matches!(unknown_type, TokenError::Malformed(_)));
    Ok(())
}


#[test]
fn a_token_without_a_role_is_refused_by_name() -> TestResult {
    let base = claims(1);
    let old = RolelessClaims {
        key_id: base.key_id,
        tenant: base.tenant,
        session_id: base.session_id,
        device_peer_id: base.device_peer_id,
        viewer_subject: base.viewer_subject,
        not_before: base.not_before,
        expires_at: base.expires_at,
        nonce: base.nonce,
    };
    let refused = refusal(&sealed(postcard::to_stdvec(&old)?)?, Role::Viewer)?;
    assert!(matches!(refused, TokenError::MissingRole));
    assert_eq!(refused.to_string(), "token has no role");
    Ok(())
}


#[test]
fn a_role_changed_outside_the_signature_is_a_bad_signature() -> TestResult {
    let token = token_for(&claims(1))?;
    let envelope: Envelope = postcard::from_bytes(&BASE64URL_NOPAD.decode(token.as_bytes())?)?;
    let role_index = 1 + KEY_ID.len();
    assert_eq!(envelope.claims.get(role_index), Some(&0));
    let mut moved = envelope.claims.clone();
    *moved.get_mut(role_index).ok_or("short")? = 1;
    let forged = Envelope { claims: moved, ..envelope };
    let forged_token = BASE64URL_NOPAD.encode(&postcard::to_stdvec(&forged)?);
    assert!(matches!(refusal(&forged_token, Role::Device)?, TokenError::BadSignature));
    Ok(())
}


#[test]
fn a_wrong_role_refusal_names_no_claim_on_any_surface() -> TestResult {
    let mut marked = claims(1);
    marked.viewer_subject = MARKER_SUBJECT.to_owned();
    let refused = refusal(&token_for(&marked)?, Role::Device)?;
    assert!(matches!(refused, TokenError::WrongRole));
    let surfaces = [refused.to_string(), format!("{refused:?}"), format!("{:?}", refused.source())];
    surfaces
        .iter()
        .for_each(|text| assert!(!text.contains(MARKER_SUBJECT) && !text.contains(PEER) && !text.contains(TENANT), "{text}"));
    Ok(())
}
