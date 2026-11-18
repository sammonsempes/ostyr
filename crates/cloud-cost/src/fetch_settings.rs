use crate::fetch_error::FetchError;
use crate::fetch_model::{FetchSettings, FetchSource};
use core_config::error::ConfigError;
use core_config::parse::{parse_document, read_file};
use core_pg::scope::tenant_scope;
use siem_ingest::settings::check_url;
use std::collections::BTreeSet;
use std::path::Path;


pub const MAX_SOURCES: usize = 64;


pub const MAX_ID_BYTES: usize = 64;


pub const MAX_PREFIX_BYTES: usize = 512;


pub const MAX_REFERENCE_BYTES: usize = 256;


pub const MAX_REGION_BYTES: usize = 64;


pub const MIN_BUCKET_BYTES: usize = 3;


pub const MAX_BUCKET_BYTES: usize = 63;


pub const MAX_OBJECTS_LIMIT: usize = 1000;


pub const MAX_FETCH_TIMEOUT_MS: u64 = 600_000;


pub fn name_char(character: char) -> bool {
    character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
}


/// Alphanumeric first, then alphanumerics and `.`, `_`, `-`: no empty segment, no leading `-` or `.`, no hidden character.
pub fn segment_ok(segment: &str) -> bool {
    segment.chars().next().is_some_and(|first| first.is_ascii_alphanumeric()) && segment.chars().all(name_char)
}


/// A path below the secrets directory: every `/` separated segment passes `segment_ok`, so there is no `..`.
pub fn reference_ok(reference: &str) -> bool {
    reference.len() <= MAX_REFERENCE_BYTES && reference.split('/').all(segment_ok)
}


/// The first path segment is the tenant: a tenant cannot name another tenant's secret.
pub fn tenant_bound(reference: &str, tenant: &str) -> bool {
    reference.strip_prefix(tenant).is_some_and(|rest| rest.starts_with('/'))
}


/// `[A-Za-z0-9._/-]` only, no `..`, no leading `/`; an empty prefix lists the whole bucket.
pub fn prefix_ok(prefix: &str) -> bool {
    prefix.len() <= MAX_PREFIX_BYTES
        && prefix.chars().all(|character| name_char(character) || character == '/')
        && !prefix.contains("..")
        && !prefix.starts_with('/')
}


pub fn bucket_ok(bucket: &str) -> bool {
    (MIN_BUCKET_BYTES..=MAX_BUCKET_BYTES).contains(&bucket.len())
        && bucket
            .chars()
            .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || matches!(character, '-' | '.'))
        && !bucket.starts_with(['-', '.'])
}


pub fn region_ok(region: &str) -> bool {
    !region.is_empty() && region.len() <= MAX_REGION_BYTES && region.chars().all(name_char)
}


pub fn ensure(condition: bool, field: &'static str) -> Result<(), FetchError> {
    if condition {
        Ok(())
    } else {
        Err(FetchError::Settings(field))
    }
}


/// Tenant by core-pg's grammar, endpoint by siem-ingest's rule, every other field by an ASCII allowlist and a bound; nothing is read or sent.
pub fn validate_source(source: &FetchSource) -> Result<(), FetchError> {
    ensure(segment_ok(&source.id) && source.id.len() <= MAX_ID_BYTES, "id")?;
    ensure(tenant_scope(&source.tenant).is_ok(), "tenant")?;
    ensure(check_url(&source.endpoint).is_ok(), "endpoint")?;
    ensure(region_ok(&source.region), "region")?;
    ensure(bucket_ok(&source.bucket), "bucket")?;
    ensure(prefix_ok(&source.prefix), "prefix")?;
    ensure(
        reference_ok(&source.credentials) && tenant_bound(&source.credentials, &source.tenant),
        "credentials",
    )?;
    ensure(source.ca_file.as_ref().is_none_or(|path| path.is_absolute()), "ca_file")?;
    ensure((1..=MAX_OBJECTS_LIMIT).contains(&source.max_objects_per_run), "max_objects_per_run")?;
    ensure((1..=MAX_FETCH_TIMEOUT_MS).contains(&source.timeout_ms), "timeout_ms")
}


/// Every source valid, at most `MAX_SOURCES`, ids unique.
pub fn validate_settings(settings: &FetchSettings) -> Result<(), FetchError> {
    ensure(settings.secrets_dir.is_absolute(), "secrets_dir")?;
    ensure(settings.sources.len() <= MAX_SOURCES, "sources")?;
    let ids: BTreeSet<&str> = settings.sources.iter().map(|source| source.id.as_str()).collect();
    ensure(ids.len() == settings.sources.len(), "id")?;
    settings.sources.iter().try_for_each(validate_source)
}


/// A refused document names the line and the field, never the text; the sources are not validated here.
pub fn parse_fetch_settings(text: &str, file: &str) -> Result<FetchSettings, ConfigError> {
    parse_document(text, file)
}


pub fn load_fetch_settings(path: &Path) -> Result<FetchSettings, ConfigError> {
    let text = read_file(path)?;
    parse_fetch_settings(&text, &path.display().to_string())
}
