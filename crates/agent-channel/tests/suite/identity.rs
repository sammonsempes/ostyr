use crate::harness::make_platform;
use crate::pki::{agent_spec, issue, LeafSpec, AGENT_URI};
use crate::types::TestResult;
use agent_channel::error::IdentityError;
use agent_channel::identity::{identity_from_certificate, identity_from_chain, parse_identity_uri, valid_component};
use agent_channel::model::{Identity, MAX_IDENTITY_COMPONENT_LENGTH};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use std::error::Error;


fn certificate_der(spec: &LeafSpec) -> Result<CertificateDer<'static>, Box<dyn Error>> {
    let platform = make_platform()?;
    let leaf = issue(&platform.agent_ca, spec)?;
    Ok(CertificateDer::from_pem_slice(leaf.certificate_pem.as_bytes())?)
}


const TWO_URIS: usize = 2;


#[test]
fn identity_comes_from_the_single_uri_name() -> TestResult {
    let der = certificate_der(&agent_spec(&[AGENT_URI]))?;
    let identity = identity_from_certificate(der.as_ref())?;
    assert_eq!(
        identity,
        Identity {
            tenant: "acme".to_string(),
            agent_id: "agent-1".to_string()
        }
    );
    Ok(())
}


#[test]
fn identity_ignores_dns_names() -> TestResult {
    let spec = LeafSpec {
        dns: vec!["agent.example".to_string()],
        ..agent_spec(&[AGENT_URI])
    };
    let identity = identity_from_certificate(certificate_der(&spec)?.as_ref())?;
    assert_eq!(identity.agent_id, "agent-1");
    Ok(())
}


#[test]
fn certificate_without_names_is_refused() -> TestResult {
    let outcome = identity_from_certificate(certificate_der(&agent_spec(&[]))?.as_ref());
    assert!(matches!(outcome, Err(IdentityError::UriCount(0))));
    Ok(())
}


#[test]
fn certificate_with_only_dns_names_is_refused() -> TestResult {
    let spec = LeafSpec {
        dns: vec!["agent.example".to_string()],
        ..agent_spec(&[])
    };
    let outcome = identity_from_certificate(certificate_der(&spec)?.as_ref());
    assert!(matches!(outcome, Err(IdentityError::UriCount(0))));
    Ok(())
}


#[test]
fn certificate_with_two_uris_is_refused() -> TestResult {
    let outcome = identity_from_certificate(certificate_der(&agent_spec(&[AGENT_URI, "urn:ostyr:agent:acme:agent-2"]))?.as_ref());
    assert!(matches!(outcome, Err(IdentityError::UriCount(TWO_URIS))));
    Ok(())
}


#[test]
fn certificate_with_a_foreign_uri_is_refused() -> TestResult {
    let outcome = identity_from_certificate(certificate_der(&agent_spec(&["https://example.com/a"]))?.as_ref());
    assert!(matches!(outcome, Err(IdentityError::BadUri(_))));
    Ok(())
}


#[test]
fn garbage_certificate_is_refused() -> TestResult {
    assert!(matches!(
        identity_from_certificate(b"not a certificate"),
        Err(IdentityError::Certificate(_))
    ));
    Ok(())
}


#[test]
fn chain_without_certificate_is_refused() -> TestResult {
    assert!(matches!(identity_from_chain(None), Err(IdentityError::NoCertificate)));
    assert!(matches!(identity_from_chain(Some(&[])), Err(IdentityError::NoCertificate)));
    Ok(())
}


#[test]
fn chain_identity_is_the_leaf_identity() -> TestResult {
    let der = certificate_der(&agent_spec(&[AGENT_URI]))?;
    let identity = identity_from_chain(Some(&[der]))?;
    assert_eq!(identity.tenant, "acme");
    Ok(())
}


#[test]
fn uri_shapes_are_checked() -> TestResult {
    let too_long = format!("urn:ostyr:agent:acme:{}", "a".repeat(MAX_IDENTITY_COMPONENT_LENGTH + 1));
    let refused = [
        "urn:ostyr:agent:acme",
        "urn:ostyr:agent::agent-1",
        "urn:ostyr:agent:acme:",
        "urn:ostyr:agent:acme:agent:1",
        "urn:ostyr:agent:ac me:agent-1",
        "urn:other:agent:acme:agent-1",
        "",
        too_long.as_str(),
    ];
    assert!(refused.iter().all(|uri| matches!(parse_identity_uri(uri), Err(IdentityError::BadUri(_)))));
    assert!(parse_identity_uri("urn:ostyr:agent:acme_1:agent-1.local").is_ok());
    Ok(())
}


#[test]
fn component_length_bound_is_inclusive() -> TestResult {
    assert!(valid_component(&"a".repeat(MAX_IDENTITY_COMPONENT_LENGTH)));
    assert!(!valid_component(&"a".repeat(MAX_IDENTITY_COMPONENT_LENGTH + 1)));
    Ok(())
}
