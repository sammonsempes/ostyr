//! Store settings (endpoint, bucket, credential files, CA, deadlines) and the opened store.

use crate::error::StoreError;
use crate::limits::{CREDENTIAL_BUFFER_CAPACITY, MAX_BUCKET_BYTES, MAX_CREDENTIAL_BYTES, MIN_BUCKET_BYTES, PRESIGN_SECONDS};
use crate::model::Store;
use crate::settings::ensure;
use crate::signing::load_private_text;
use crate::types::HttpFn;
use rusty_s3::{Bucket, Credentials, UrlStyle};
use serde::Deserialize;
use std::path::{Path, PathBuf};
use std::time::Duration;
use url::Url;
use zeroize::Zeroizing;


#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoreSettings {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub ca_file: Option<PathBuf>,
    pub access_key_file: PathBuf,
    pub secret_key_file: PathBuf,
    pub connect_millis: u64,
    pub read_millis: u64,
    pub total_millis: u64,
}


/// Path-style URLs (MinIO); a scheme other than https is refused, which `Bucket::new` alone would accept for http.
pub fn open_bucket(settings: &StoreSettings) -> Result<Bucket, StoreError> {
    let endpoint = Url::parse(&settings.endpoint).map_err(|_refused| StoreError::Settings("endpoint"))?;
    let bucket = Bucket::new(endpoint, UrlStyle::Path, settings.bucket.clone(), settings.region.clone())?;
    ensure(bucket.base_url().scheme() == "https", StoreError::Settings("endpoint"))?;
    Ok(bucket)
}


fn bucket_name_ok(name: &str) -> bool {
    (MIN_BUCKET_BYTES..=MAX_BUCKET_BYTES).contains(&name.len())
        && name
            .chars()
            .all(|character| character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-' || character == '.')
        && !name.starts_with(['-', '.'])
}


/// TLS endpoint, a plausible bucket name, absolute files, and every deadline above zero and within the total.
pub fn validate_store_settings(settings: &StoreSettings) -> Result<(), StoreError> {
    open_bucket(settings)?;
    ensure(bucket_name_ok(&settings.bucket), StoreError::Settings("bucket"))?;
    ensure(!settings.region.is_empty(), StoreError::Settings("region"))?;
    ensure(settings.access_key_file.is_absolute(), StoreError::Settings("access_key_file"))?;
    ensure(settings.secret_key_file.is_absolute(), StoreError::Settings("secret_key_file"))?;
    ensure(
        settings.ca_file.as_ref().is_none_or(|path| path.is_absolute()),
        StoreError::Settings("ca_file"),
    )?;
    ensure(settings.connect_millis > 0, StoreError::Settings("connect_millis"))?;
    ensure(settings.read_millis > 0, StoreError::Settings("read_millis"))?;
    ensure(
        settings.total_millis >= settings.connect_millis.max(settings.read_millis),
        StoreError::Settings("total_millis"),
    )
}


/// A credential file follows the key-file pattern: private mode, owned by the process, read from the checked handle under a cap.
pub fn read_credential(path: &Path) -> Result<Zeroizing<String>, StoreError> {
    let text = load_private_text(path, MAX_CREDENTIAL_BYTES, CREDENTIAL_BUFFER_CAPACITY)?;
    let trimmed = text.trim();
    ensure(!trimmed.is_empty() && !trimmed.chars().any(char::is_control), StoreError::BadCredential)?;
    Ok(Zeroizing::new(trimmed.to_owned()))
}


/// The credentials live in `rusty-s3`, which keeps its own copy of the strings.
pub fn open_store(settings: &StoreSettings, http: Box<HttpFn>) -> Result<Store, StoreError> {
    validate_store_settings(settings)?;
    let access_key = read_credential(&settings.access_key_file)?;
    let secret_key = read_credential(&settings.secret_key_file)?;
    Ok(Store {
        bucket: open_bucket(settings)?,
        credentials: Credentials::new(access_key.as_str(), secret_key.as_str()),
        expiry: Duration::from_secs(PRESIGN_SECONDS),
        http,
    })
}
