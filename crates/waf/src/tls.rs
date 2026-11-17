use crate::error::WafError;
use crate::limits::{
    CA_ROOT_LABEL, CA_ROOT_PREFIX, CA_ROOT_SUFFIX, DEFAULT_HSTS_SECONDS, HTTPS_PREFIX, MAX_CA_ROOT_BYTES, MAX_DIRECTORY_BYTES, MAX_EMAIL_BYTES,
    MAX_HSTS_SECONDS, MAX_LOCAL_BYTES, MAX_PORT_DIGITS, PEM_BEGIN, PEM_CERTIFICATE_BEGIN, PEM_CERTIFICATE_END, PEM_DASHES, PEM_LINE_CHARS,
};
use crate::model::{CaRoot, Issuer, RawIssuer, RawTls, Tls};
use crate::validate::{check_host, check_raw_path};
use core_config::parse::read_text_capped;
use data_encoding::{BASE64, HEXLOWER};
#[cfg(target_os = "linux")]
use rustix::fd::AsRawFd;
#[cfg(target_os = "linux")]
use rustix::fs::{fstat, open, FileType, Mode, OFlags};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::CertificateDer;
use sha2::{Digest, Sha256};
use std::fs::File;
use x509_parser::parse_x509_certificate;


pub const ACME_FIELDS_MISSING: &str = "the acme issuer needs a directory and an email";


pub const INTERNAL_FIELDS: &str = "the internal issuer takes no directory, email or ca_root_file";


pub const BAD_DIRECTORY: &str = "invalid directory";


pub const BAD_EMAIL: &str = "invalid email";


pub const BAD_CA_ROOT_PATH: &str = "invalid ca_root_file path";


pub const NO_CERTIFICATE: &str = "ca_root_file holds no certificate";


pub const NOT_ONLY_CERTIFICATES: &str = "ca_root_file holds a section that is not a certificate";


pub const NOT_REGULAR_FILE: &str = "ca_root_file is not a regular file";


pub const NOT_X509: &str = "ca_root_file holds a certificate section that is not an X.509 certificate";


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


/// One certificate as PEM, 64 characters a line.
pub fn encode_certificate(der: &[u8]) -> String {
    let characters: Vec<char> = BASE64.encode(der).chars().collect();
    let lines: Vec<String> = characters.chunks(PEM_LINE_CHARS).map(|line| line.iter().collect()).collect();
    format!("{PEM_CERTIFICATE_BEGIN}\n{}\n{PEM_CERTIFICATE_END}\n", lines.join("\n"))
}


/// A line that starts like a PEM marker and is not the certificate marker: a malformed or foreign section, never silently dropped.
pub fn stray_marker(text: &str) -> bool {
    text.lines()
        .map(str::trim)
        .any(|line| line.starts_with(PEM_DASHES) && line != PEM_CERTIFICATE_BEGIN && line != PEM_CERTIFICATE_END)
}


/// True when the DER is exactly one X.509 certificate, with nothing after it.
pub fn is_x509(der: &[u8]) -> bool {
    parse_x509_certificate(der).is_ok_and(|(rest, _)| rest.is_empty())
}


/// The certificates of `text` re-encoded as PEM, nothing else of the text; a section that is not a certificate or a malformed one refuses it all.
pub fn check_pem(text: &str) -> Result<String, &'static str> {
    if stray_marker(text) {
        Err(NOT_ONLY_CERTIFICATES)?;
    }
    let certificates = CertificateDer::pem_slice_iter(text.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| NO_CERTIFICATE)?;
    if text.matches(PEM_BEGIN).count() != certificates.len() {
        Err(NOT_ONLY_CERTIFICATES)
    } else if certificates.is_empty() {
        Err(NO_CERTIFICATE)
    } else if !certificates.iter().all(|der| is_x509(der)) {
        Err(NOT_X509)
    } else {
        Ok(certificates.iter().map(|der| encode_certificate(der)).collect())
    }
}


/// A failed system call as the error that names the CA root file.
#[cfg(target_os = "linux")]
pub fn read_failure(errno: rustix::io::Errno) -> WafError {
    WafError::CaRoot(errno.into())
}


/// Opens by `O_PATH`, which has no side effect even on a device, judges that handle, and only a regular file is reopened without blocking.
#[cfg(target_os = "linux")]
pub fn open_regular(path: &str) -> Result<File, WafError> {
    let anchor = open(path, OFlags::PATH | OFlags::CLOEXEC, Mode::empty()).map_err(read_failure)?;
    let stat = fstat(&anchor).map_err(read_failure)?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
        let proc_path = format!("/proc/self/fd/{}", anchor.as_raw_fd());
        let descriptor = open(proc_path.as_str(), OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC, Mode::empty()).map_err(read_failure)?;
        Ok(File::from(descriptor))
    } else {
        Err(WafError::BadTls(NOT_REGULAR_FILE))
    }
}


/// Opens the file and keeps it only if it is a regular file.
#[cfg(not(target_os = "linux"))]
pub fn open_regular(path: &str) -> Result<File, WafError> {
    let file = File::open(path).map_err(WafError::CaRoot)?;
    if file.metadata().map_err(WafError::CaRoot)?.is_file() {
        Ok(file)
    } else {
        Err(WafError::BadTls(NOT_REGULAR_FILE))
    }
}


/// Opens the file once and keeps the bytes of that one read: only its certificates, re-encoded, are kept and named by their SHA-256.
pub fn check_ca_root(path: &str) -> Result<CaRoot, WafError> {
    let checked = check_raw_path(path).map_err(|_| WafError::BadTls(BAD_CA_ROOT_PATH))?;
    let mut file = open_regular(checked)?;
    let text = read_text_capped(&mut file, CA_ROOT_LABEL, MAX_CA_ROOT_BYTES)?;
    let pem = check_pem(&text).map_err(WafError::BadTls)?;
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
