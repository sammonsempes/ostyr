use crate::error::IdentityError;
use crate::model::{Identity, IDENTITY_URI_PREFIX, MAX_IDENTITY_COMPONENT_LENGTH};
use rustls_pki_types::CertificateDer;
use x509_parser::certificate::X509Certificate;
use x509_parser::extensions::GeneralName;
use x509_parser::parse_x509_certificate;


/// Identity of the leaf certificate of a verified peer chain; `None` means the peer sent no certificate.
pub fn identity_from_chain(chain: Option<&[CertificateDer<'_>]>) -> Result<Identity, IdentityError> {
    let leaf = chain.and_then(<[CertificateDer<'_>]>::first).ok_or(IdentityError::NoCertificate)?;
    identity_from_certificate(leaf.as_ref())
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
