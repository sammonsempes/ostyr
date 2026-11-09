use crate::error::SettingsError;
use crate::settings::{check_present, check_range, IngestSettings, LOOPBACK_HOSTS};
use std::path::PathBuf;
use ureq::http::Uri;


pub const DEFAULT_NATS_URL: &str = "nats://127.0.0.1:4222";


pub const DEFAULT_NATS_STREAM: &str = "events";


pub const DEFAULT_NATS_CONSUMER: &str = "siem-ingest";


pub const DEFAULT_DEAD_LETTER_SUBJECT: &str = "dead.events";


pub const DEFAULT_NATS_FETCH_DEADLINE_MS: u64 = 2000;


pub const DEFAULT_NATS_REQUEST_TIMEOUT_MS: u64 = 5000;


pub const DEFAULT_NATS_ACK_WAIT_MS: u64 = 30_000;


pub const DEFAULT_NATS_PING_INTERVAL_MS: u64 = 10_000;


pub const DEFAULT_NATS_MAX_HEADERS: usize = 16;


pub const LIMIT_NATS_MS: u64 = 600_000;


pub const LIMIT_NATS_MAX_HEADERS: usize = 128;


pub const LIMIT_NATS_NAME_BYTES: usize = 64;


pub const LIMIT_NATS_SUBJECT_BYTES: usize = 128;


pub const EVENTS_STREAM_TOKEN: &str = "events";


pub fn is_name_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '-' || character == '_'
}


/// A stream or consumer name: one NATS token of letters, numbers, `-` and `_`.
pub fn check_name(field: &'static str, value: &str) -> Result<(), SettingsError> {
    if !value.is_empty() && value.len() <= LIMIT_NATS_NAME_BYTES && value.chars().all(is_name_character) {
        Ok(())
    } else {
        Err(SettingsError::Invalid {
            field,
            reason: "must be 1 to 64 letters, numbers, `-` or `_`",
        })
    }
}


/// A literal subject outside `events.>`, or the dead letters would be consumed again.
pub fn check_dead_letter_subject(value: &str) -> Result<(), SettingsError> {
    let tokens_ok = value.split('.').all(|token| !token.is_empty() && token.chars().all(is_name_character));
    let first_token = value.split('.').next();
    if tokens_ok && value.len() <= LIMIT_NATS_SUBJECT_BYTES && first_token != Some(EVENTS_STREAM_TOKEN) {
        Ok(())
    } else {
        Err(SettingsError::Invalid {
            field: "nats_dead_letter_subject",
            reason: "must be a literal subject that is not under `events`",
        })
    }
}


/// `tls://`, or `nats://` on loopback or with the handshake-first TLS mode; no userinfo, query or fragment.
pub fn check_nats_url(value: &str, tls_first: bool) -> Result<(), SettingsError> {
    let parsed = value.parse::<Uri>().ok();
    let scheme = parsed.as_ref().and_then(Uri::scheme_str);
    let loopback = parsed.as_ref().and_then(Uri::host).is_some_and(|host| LOOPBACK_HOSTS.contains(&host));
    let scheme_ok = scheme == Some("tls") || (scheme == Some("nats") && (loopback || tls_first));
    let bare = !value.contains(['?', '#', '@']);
    if scheme_ok && bare {
        Ok(())
    } else {
        Err(SettingsError::Invalid {
            field: "nats_url",
            reason: "must be tls://, or nats:// on loopback or with nats_tls_first, without userinfo, query or fragment",
        })
    }
}


pub fn check_optional_path(field: &'static str, path: Option<&PathBuf>) -> Result<(), SettingsError> {
    path.map_or(Ok(()), |present| check_present(field, &present.to_string_lossy()))
}


/// A user and its password file go together, and neither combines with a credentials file.
pub fn check_auth(settings: &IngestSettings) -> Result<(), SettingsError> {
    let user = settings.nats_user.as_deref();
    let paired = user.is_some() == settings.nats_password_file.is_some();
    let single = user.is_none() || settings.nats_credentials_file.is_none();
    if paired && single {
        user.map_or(Ok(()), |name| check_present("nats_user", name))
    } else {
        Err(SettingsError::Invalid {
            field: "nats_user",
            reason: "needs nats_password_file, and excludes nats_credentials_file",
        })
    }
}


/// Every NATS value is bounded; the JetStream names and the dead-letter subject are literal tokens.
pub fn validate_nats_settings(settings: &IngestSettings) -> Result<(), SettingsError> {
    check_nats_url(&settings.nats_url, settings.nats_tls_first)?;
    check_name("nats_stream", &settings.nats_stream)?;
    check_name("nats_consumer", &settings.nats_consumer)?;
    check_dead_letter_subject(&settings.nats_dead_letter_subject)?;
    check_range("nats_fetch_deadline_ms", settings.nats_fetch_deadline_ms, LIMIT_NATS_MS)?;
    check_range("nats_request_timeout_ms", settings.nats_request_timeout_ms, LIMIT_NATS_MS)?;
    check_range("nats_ack_wait_ms", settings.nats_ack_wait_ms, LIMIT_NATS_MS)?;
    check_range("nats_ping_interval_ms", settings.nats_ping_interval_ms, LIMIT_NATS_MS)?;
    check_range("nats_max_headers", settings.nats_max_headers as u64, LIMIT_NATS_MAX_HEADERS as u64)?;
    check_optional_path("nats_ca_file", settings.nats_ca_file.as_ref())?;
    check_optional_path("nats_password_file", settings.nats_password_file.as_ref())?;
    check_auth(settings)?;
    check_optional_path("nats_credentials_file", settings.nats_credentials_file.as_ref())
}
