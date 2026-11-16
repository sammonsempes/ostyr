use crate::error::WafError;
use crate::limits::{
    CA_ROOT_LABEL, CA_ROOT_PREFIX, CA_ROOT_SUFFIX, DEFAULT_HSTS_SECONDS, HTTPS_PREFIX, MAX_CA_ROOT_BYTES, MAX_DIRECTORY_BYTES, MAX_EMAIL_BYTES,
    MAX_HSTS_SECONDS, MAX_LOCAL_BYTES, MAX_PORT_DIGITS,
};
use crate::model::{CaRoot, Issuer, RawIssuer, RawTls, Tls};
use crate::validate::{check_host, check_raw_path};
use core_config::parse::read_text_capped;
use data_encoding::HEXLOWER;
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::fs::File;


pub const ACME_FIELDS_MISSING: &str = "the acme issuer needs a directory and an email";


pub const INTERNAL_FIELDS: &str = "the internal issuer takes no directory, email or ca_root_file";


pub const BAD_DIRECTORY: &str = "invalid directory";


pub const BAD_EMAIL: &str = "invalid email";


pub const BAD_CA_ROOT_PATH: &str = "invalid ca_root_file path";


pub const NO_CERTIFICATE: &str = "ca_root_file holds no certificate";


pub const BAD_HSTS: &str = "invalid hsts_max_age_seconds";


fn valid_port(port: &str) -> bool {
    let digits = !port.is_empty() && port.len() <= MAX_PORT_DIGITS && port.chars().all(|character| character.is_ascii_digit());
    digits && port.parse::<u16>().is_ok_and(|number| number > 0)
}


/// An `https://` URL of an ASCII host, an optional port and a path of `-._~/` and alphanumerics: no userinfo, query or escape.
pub fn check_directory(directory: &str) -> Result<String, &'static str> {
    let rest = directory.strip_prefix(HTTPS_PREFIX).ok_or(BAD_DIRECTORY)?;
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let (host, port) = authority.split_once(':').map_or((authority, None), |(name, number)| (name, Some(number)));
    let path_allowed = path
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "-._~/".contains(character));
    if directory.len() <= MAX_DIRECTORY_BYTES && check_host(host).is_ok() && port.is_none_or(valid_port) && path_allowed {
        Ok(directory.to_string())
    } else {
        Err(BAD_DIRECTORY)
    }
}


/// `local@host`: a local part of letters, digits and `._+-` not starting with `-`, and an ASCII DNS host.
pub fn check_email(email: &str) -> Result<String, &'static str> {
    let (local, host) = email.split_once('@').ok_or(BAD_EMAIL)?;
    let local_allowed = !local.is_empty()
        && local.len() <= MAX_LOCAL_BYTES
        && !local.starts_with('-')
        && local
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._+-".contains(character));
    let host_name = check_host(host).map_err(|_| BAD_EMAIL)?;
    if local_allowed && email.len() <= MAX_EMAIL_BYTES {
        Ok(format!("{local}@{host_name}"))
    } else {
        Err(BAD_EMAIL)
    }
}


/// The `Strict-Transport-Security` value, none for a max age of 0.
pub fn check_hsts(max_age: Option<u64>, include_subdomains: bool) -> Result<Option<String>, &'static str> {
    let seconds = max_age.unwrap_or(DEFAULT_HSTS_SECONDS);
    if seconds > MAX_HSTS_SECONDS {
        Err(BAD_HSTS)
    } else if seconds == 0 {
        Ok(None)
    } else if include_subdomains {
        Ok(Some(format!("max-age={seconds}; includeSubDomains")))
    } else {
        Ok(Some(format!("max-age={seconds}")))
    }
}


/// At least one certificate and no malformed PEM block.
pub fn check_pem(text: &str) -> Result<(), &'static str> {
    let certificates = CertificateDer::pem_slice_iter(text.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NO_CERTIFICATE)?;
    if certificates.is_empty() {
        Err(NO_CERTIFICATE)
    } else {
        Ok(())
    }
}


/// Opens the file once and keeps the bytes of that one read: the bytes checked are the bytes written, named by their SHA-256.
pub fn check_ca_root(path: &str) -> Result<CaRoot, WafError> {
    let checked = check_raw_path(path).map_err(|_| WafError::BadTls(BAD_CA_ROOT_PATH))?;
    let mut file = File::open(checked).map_err(WafError::CaRoot)?;
    let pem = read_text_capped(&mut file, CA_ROOT_LABEL, MAX_CA_ROOT_BYTES)?;
    check_pem(&pem).map_err(WafError::BadTls)?;
    let name = format!("{CA_ROOT_PREFIX}{}{CA_ROOT_SUFFIX}", HEXLOWER.encode(&Sha256::digest(pem.as_bytes())));
    Ok(CaRoot { name, pem })
}


fn acme_issuer(raw: RawTls) -> Result<Issuer, WafError> {
    match (raw.directory, raw.email) {
        (Some(directory), Some(email)) => {
            let checked_directory = check_directory(&directory).map_err(WafError::BadTls)?;
            let checked_email = check_email(&email).map_err(WafError::BadTls)?;
            let ca_root = raw.ca_root_file.as_deref().map(check_ca_root).transpose()?;
            Ok(Issuer::Acme {
                directory: checked_directory,
                email: checked_email,
                ca_root,
            })
        }
        _ => Err(WafError::BadTls(ACME_FIELDS_MISSING)),
    }
}


/// Validates the `tls:` section; any failure refuses the whole file.
pub fn check_tls(raw: RawTls) -> Result<Tls, WafError> {
    let hsts = check_hsts(raw.hsts_max_age_seconds, raw.hsts_include_subdomains).map_err(WafError::BadTls)?;
    let issuer = match raw.issuer {
        RawIssuer::Internal if raw.directory.is_none() && raw.email.is_none() && raw.ca_root_file.is_none() => Ok(Issuer::Internal),
        RawIssuer::Internal => Err(WafError::BadTls(INTERNAL_FIELDS)),
        RawIssuer::Acme => acme_issuer(raw),
    }?;
    Ok(Tls { issuer, hsts })
}
