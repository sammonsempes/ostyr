use crate::fetch_error::{FetchError, Refusal};
use crate::fetch_model::{FetchEnv, FetchReport, FetchSettings, FetchSource, ListedObject, ObjectOutcome, SourceRun};
use crate::fetch_settings::validate_source;
use crate::ledger::{is_loaded, record_loaded};
use crate::listing::{get_body, list_objects, open_bucket, PRESIGN_SECONDS};
use crate::load::LoadError;
use crate::source::read_export;
use core_config::secret_file::open_secret;
use flate2::read::GzDecoder;
use log::{info, warn};
use rusty_s3::{Credentials, S3Action};
use sha2::{Digest, Sha256};
use siem_ingest::error::{InsertClass, InsertError};
use std::io::{Cursor, Read};
use std::path::Path;
use std::time::Duration;


pub const MAX_CREDENTIAL_BYTES: u64 = 1024;


pub const DIGEST_CHARS: usize = 16;


pub const GZIP_SUFFIX: &str = ".gz";


/// The first 16 hex characters of the key's SHA-256: a log names an object by it, never by the key text.
pub fn key_digest(key: &str) -> String {
    format!("{:x}", Sha256::digest(key.as_bytes())).chars().take(DIGEST_CHARS).collect()
}


fn credential_line_ok(line: &str) -> bool {
    !line.is_empty() && line.chars().all(|character| character.is_ascii_graphic())
}


/// Two lines, the access key then the secret key, printable ASCII, the whole file within `MAX_CREDENTIAL_BYTES`.
pub fn parse_credentials(text: &str) -> Result<Credentials, FetchError> {
    let lines: Vec<&str> = text.lines().map(str::trim).collect();
    match lines.as_slice() {
        [access, secret] if text.len() as u64 <= MAX_CREDENTIAL_BYTES && credential_line_ok(access) && credential_line_ok(secret) => {
            Ok(Credentials::new(*access, *secret))
        }
        _ => Err(FetchError::BadCredentials),
    }
}


/// Opened by the shared secret reader (regular file, no symlink, owned by the process user or root, no group or other bit), read under a cap.
pub fn read_credentials(path: &Path) -> Result<Credentials, FetchError> {
    let file = open_secret(path).map_err(FetchError::Credentials)?;
    let mut text = String::new();
    file.take(MAX_CREDENTIAL_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| FetchError::CredentialsRead(error.kind()))?;
    parse_credentials(&text)
}


/// The decompressed size is capped like the download: a gzip bomb is that object's refusal, never an allocation.
pub fn gunzip_capped(body: &[u8], max_bytes: u64) -> Result<Vec<u8>, Refusal> {
    let mut decoded = Vec::new();
    GzDecoder::new(body)
        .take(max_bytes.saturating_add(1))
        .read_to_end(&mut decoded)
        .map_err(|_error| Refusal::BadGzip)?;
    if decoded.len() as u64 > max_bytes {
        Err(Refusal::TooLarge)
    } else {
        Ok(decoded)
    }
}


pub fn object_url(run: &SourceRun<'_>, key: &str) -> String {
    run.bucket
        .get_object(Some(&run.credentials), key)
        .sign(Duration::from_secs(PRESIGN_SECONDS))
        .to_string()
}


/// The download is read under `max_bytes + 1`, so an endless body stops at the cap.
pub fn object_bytes(run: &SourceRun<'_>, object: &ListedObject) -> Result<Vec<u8>, Refusal> {
    let max_bytes = run.env.limits.max_bytes;
    let body = get_body(run.env, run.source, object_url(run, &object.key), max_bytes.saturating_add(1))?;
    if body.len() as u64 > max_bytes {
        Err(Refusal::TooLarge)
    } else if object.key.ends_with(GZIP_SUFFIX) {
        gunzip_capped(&body, max_bytes)
    } else {
        Ok(body)
    }
}


/// The fixed class of a failed load when it has one; a server message is never read, so nothing else is kept.
pub fn load_class(error: &LoadError) -> Option<InsertClass> {
    match error {
        LoadError::Replace { class, .. } | LoadError::Schema(class) | LoadError::Agent(InsertError::Class(class)) => Some(*class),
        _other => None,
    }
}


/// Download, parse, load into ClickHouse, then the ledger row: the ledger is written only after the load succeeded.
pub fn fetch_object(run: &SourceRun<'_>, object: &ListedObject, now: u64) -> Result<(), Refusal> {
    let bytes = object_bytes(run, object)?;
    let export = read_export(Cursor::new(bytes), run.env.limits, &run.source.tenant).map_err(|_error| Refusal::Unreadable)?;
    let outcome = (run.env.load)(&run.source.tenant, &export).map_err(|error| Refusal::Load(load_class(&error)))?;
    if let Some(failure) = outcome.failure {
        Err(Refusal::Load(Some(failure.class)))
    } else {
        record_loaded(run.env.exec, &run.source.tenant, &run.source.id, object, &export.source, now).map_err(|_error| Refusal::Ledger)
    }
}


pub fn process_object(run: &SourceRun<'_>, object: &ListedObject, now: u64) -> ObjectOutcome {
    match is_loaded(run.env.exec, &run.source.tenant, &run.source.id, object) {
        Err(_failure) => ObjectOutcome::Refused(Refusal::Ledger),
        Ok(true) => ObjectOutcome::AlreadyLoaded,
        Ok(false) => match fetch_object(run, object, now) {
            Ok(()) => ObjectOutcome::Loaded,
            Err(refusal) => ObjectOutcome::Refused(refusal),
        },
    }
}


/// Objects past `max_objects_per_run` attempts are not even looked up this round and count as `deferred`.
pub fn handle_object(mut report: FetchReport, run: &SourceRun<'_>, object: &ListedObject, now: u64) -> FetchReport {
    if report.loaded + report.refused.len() >= run.source.max_objects_per_run {
        report.deferred += 1;
    } else {
        match process_object(run, object, now) {
            ObjectOutcome::Loaded => report.loaded += 1,
            ObjectOutcome::AlreadyLoaded => report.already_loaded += 1,
            ObjectOutcome::Refused(refusal) => {
                let digest = key_digest(&object.key);
                warn!("object refused: key digest {digest}, {refusal:?}");
                report.refused.push((digest, refusal));
            }
        }
    }
    report
}


/// One source: settings checked, credentials read, listing walked, then each object handled alone.
pub fn fetch_source(settings: &FetchSettings, source: &FetchSource, env: &FetchEnv<'_>, now: u64) -> Result<FetchReport, FetchError> {
    validate_source(source)?;
    let credentials = read_credentials(&settings.secrets_dir.join(&source.credentials))?;
    let bucket = open_bucket(source)?;
    let listing = list_objects(env, source, &bucket, &credentials)?;
    let run = SourceRun {
        env,
        source,
        bucket,
        credentials,
    };
    let start = FetchReport {
        listed: listing.objects.len(),
        skipped_key: listing.skipped_key,
        incomplete_listings: usize::from(listing.incomplete),
        ..FetchReport::default()
    };
    Ok(listing
        .objects
        .iter()
        .fold(start, |report, object| handle_object(report, &run, object, now)))
}


pub fn merge_reports(mut total: FetchReport, found: FetchReport) -> FetchReport {
    total.listed += found.listed;
    total.skipped_key += found.skipped_key;
    total.already_loaded += found.already_loaded;
    total.loaded += found.loaded;
    total.deferred += found.deferred;
    total.incomplete_listings += found.incomplete_listings;
    total.refused.extend(found.refused);
    total.failed_sources.extend(found.failed_sources);
    total
}


pub fn fold_source(total: FetchReport, settings: &FetchSettings, source: &FetchSource, env: &FetchEnv<'_>, now: u64) -> FetchReport {
    match fetch_source(settings, source, env, now) {
        Ok(found) => {
            let (id, loaded, refused) = (&source.id, found.loaded, found.refused.len());
            info!("source {id}: {loaded} loaded, {refused} refused");
            merge_reports(total, found)
        }
        Err(error) => {
            warn!("source {} failed: {error}", source.id);
            merge_reports(
                total,
                FetchReport {
                    failed_sources: vec![(source.id.clone(), error)],
                    ..FetchReport::default()
                },
            )
        }
    }
}


/// One round over the snapshot: a failed source is reported and the others go on; an object that was loaded before is not downloaded again.
pub fn fetch_new(settings: &FetchSettings, env: &FetchEnv<'_>, now: u64) -> FetchReport {
    settings
        .sources
        .iter()
        .fold(FetchReport::default(), |total, source| fold_source(total, settings, source, env, now))
}
