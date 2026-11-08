use crate::error::IdentityError;
use crate::model::{Identity, IDENTITY_URI_PREFIX, MAX_IDENTITY_COMPONENT_LENGTH, SERIAL_SIGN_BIT};
use crate::revocation::canonical_serial;
use data_encoding::HEXLOWER;
use rustls_pki_types::CertificateDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;


/// Identity of the leaf certificate of a verified peer chain; `None` means the peer sent no certificate.
pub fn identity_from_chain(chain: Option<&[CertificateDer<'_>]>) -> Result<Identity, IdentityError> {
    let leaf = chain.and_then(<[CertificateDer<'_>]>::first).ok_or(IdentityError::NoCertificate)?;
    identity_from_certificate(leaf.as_ref())
}


/// Serials of every certificate the peer sent (leaf first, then intermediates), in the form kept by the revocation list.
pub fn serials_from_chain(chain: Option<&[CertificateDer<'_>]>) -> Result<Vec<String>, IdentityError> {
    let certificates = chain.filter(|sent| !sent.is_empty()).ok_or(IdentityError::NoCertificate)?;
    certificates
        .iter()
        .map(|certificate| serial_from_certificate(certificate.as_ref()))
        .collect()
}


pub fn serial_from_certificate(der: &[u8]) -> Result<String, IdentityError> {
    let (_, certificate) = parse_x509_certificate(der).map_err(IdentityError::Certificate)?;
    if certificate.raw_serial().first().is_some_and(|byte| byte & SERIAL_SIGN_BIT != 0) {
        Err(IdentityError::NegativeSerial)
    } else {
        Ok(canonical_serial(&HEXLOWER.encode(certificate.raw_serial())))
    }
}


/// The certificate must carry exactly one URI name, of the form `urn:ostyr:agent:<tenant>:<agent-id>`.
pub fn identity_from_certificate(der: &[u8]) -> Result<Identity, IdentityError> {
    let (_, certificate) = parse_x509_certificate(der).map_err(IdentityError::Certificate)?;
    let uris = uri_names(&certificate)?;
    match uris.as_slice() {
        [uri] => parse_identity_uri(uri),
        other => Err(IdentityError::UriCount(other.len())),
    }
}


pub fn uri_names(certificate: &X509Certificate<'_>) -> Result<Vec<String>, IdentityError> {
    let names = certificate.subject_alternative_name().map_err(IdentityError::Names)?;
    Ok(names.map_or_else(Vec::new, |extension| {
        extension
            .value
            .general_names
            .iter()
            .filter_map(|name| match name {
                GeneralName::URI(uri) => Some((*uri).to_string()),
                _ => None,
            })
            .collect()
    }))
}


pub fn parse_identity_uri(uri: &str) -> Result<Identity, IdentityError> {
    let (tenant, agent_id) = uri
        .strip_prefix(IDENTITY_URI_PREFIX)
        .and_then(|rest| rest.split_once(':'))
        .filter(|(tenant, agent_id)| valid_component(tenant) && valid_component(agent_id))
        .ok_or_else(|| IdentityError::BadUri(uri.to_string()))?;
    Ok(Identity {
        tenant: tenant.to_string(),
        agent_id: agent_id.to_string(),
    })
}


pub fn valid_component(component: &str) -> bool {
    !component.is_empty()
        && component.len() <= MAX_IDENTITY_COMPONENT_LENGTH
        && component
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.'))
}
