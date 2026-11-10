use crate::error::DetectionError;
use crate::model::{DetectionFile, FixedPaths};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::Subscriber;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine};
use core_config::types::{BoxError, LoaderFn, SharedAuditFn};
use core_pg::settings::{settings_state as pg_state, PgSettings};
use siem_ingest::error::{IngestError, SettingsError};
use siem_ingest::nats_settings::DEFAULT_NATS_CONSUMER;
use siem_ingest::settings::{settings_state, validate_settings, IngestSettings, SECTION};
use std::path::{Path, PathBuf};
use stream_correlation::reload::{load_rules, rules_state};
use stream_correlation::ruleset::RuleSet;


const HALF: u64 = 2;


pub fn load_detection_file(path: &Path) -> Result<DetectionFile, DetectionError> {
    Ok(load_file::<DetectionFile>(path)?)
}


pub fn fixed_paths(file: &DetectionFile) -> FixedPaths {
    FixedPaths {
        audit_file: file.audit_file.clone(),
        checkpoint_dir: file.checkpoint_dir.clone(),
        alerts_file: file.alerts_file.clone(),
        sink: file.sink,
    }
}


/// The baseline is what the service read at start; a file that changes a start-only setting is refused (so audited), never silently ignored.
pub fn check_fixed(baseline: &FixedPaths, file: DetectionFile) -> Result<DetectionFile, ConfigError> {
    if fixed_paths(&file) == *baseline {
        Ok(file)
    } else {
        Err(ConfigError::WatchedFile {
            file: "audit_file, checkpoint_dir, alerts_file, sink".to_owned(),
            reason: "read at start only, restart the service to change it".to_owned(),
        })
    }
}


pub fn load_checked(path: &Path, baseline: &FixedPaths) -> Result<DetectionFile, ConfigError> {
    check_fixed(baseline, load_file::<DetectionFile>(path)?)
}


/// The service needs its own durable consumer: with the siem-ingest default name the two services would share one and each see half of the events.
pub fn check_consumer(settings: &IngestSettings) -> Result<(), SettingsError> {
    if settings.nats_consumer == DEFAULT_NATS_CONSUMER {
        Err(SettingsError::Invalid {
            field: "nats_consumer",
            reason: "must name this service's own durable consumer, not the siem-ingest default",
        })
    } else {
        Ok(())
    }
}


/// A progress ack goes out once the waited backoff passes half of `ack_wait`, so one backoff step must stay below that half.
pub fn check_backoff(settings: &IngestSettings) -> Result<(), SettingsError> {
    if settings.backoff_max_ms >= settings.nats_ack_wait_ms / HALF {
        Err(SettingsError::Invalid {
            field: "backoff_max_ms",
            reason: "must stay below half of nats_ack_wait_ms, so a progress ack goes out before the ack wait",
        })
    } else {
        Ok(())
    }
}


pub fn validate_ingest(settings: &IngestSettings) -> Result<(), SettingsError> {
    validate_settings(settings)
        .and_then(|()| check_consumer(settings))
        .and_then(|()| check_backoff(settings))
}


pub fn ingest_subscriber() -> Subscriber<IngestSettings> {
    Subscriber {
        section: SECTION.to_owned(),
        validate: Box::new(|settings| validate_ingest(settings).map_err(BoxError::from)),
        apply: Box::new(|_| ()),
    }
}


/// The `ingest` section of the service file as the bus adapter's settings; fails on an unreadable file or invalid first settings, a later invalid file is refused and the old settings stay.
pub fn open_ingest(
    path: PathBuf,
    baseline: FixedPaths,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<ReloadEngine<IngestSettings>, DetectionError> {
    let engine = open_engine(
        Box::new(move || load_checked(&path, &baseline).map(|file| file.ingest)),
        settings_state,
        vec![ingest_subscriber()],
        audit,
        context,
    )?;
    validate_ingest(&current_config(&engine)).map_err(IngestError::Settings)?;
    Ok(engine)
}


/// Reads the service file, then the mapping and every rule file it names, on each reload: the list of rule files changes live too.
pub fn rules_loader(path: PathBuf, baseline: FixedPaths) -> Box<LoaderFn<RuleSet>> {
    Box::new(move || {
        let file = load_checked(&path, &baseline)?;
        load_rules(&file.mapping_file, &file.rule_files)
    })
}


pub fn open_rules_engine(
    path: PathBuf,
    baseline: FixedPaths,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<ReloadEngine<RuleSet>, DetectionError> {
    Ok(open_engine(rules_loader(path, baseline), rules_state, Vec::new(), audit, context)?)
}


/// The `postgres` section of the service file; the postgres sink refuses a file without it.
pub fn postgres_of(file: DetectionFile) -> Result<PgSettings, ConfigError> {
    file.postgres.ok_or_else(|| ConfigError::WatchedFile {
        file: "postgres".to_owned(),
        reason: "the postgres sink needs a `postgres` section".to_owned(),
    })
}


/// Read again on every reload: the next connection uses the new settings, an invalid file is refused and the old ones stay.
pub fn open_pg_engine(
    path: PathBuf,
    baseline: FixedPaths,
    audit: Box<SharedAuditFn>,
    context: ReloadContext,
) -> Result<ReloadEngine<PgSettings>, DetectionError> {
    Ok(open_engine(
        Box::new(move || load_checked(&path, &baseline).and_then(postgres_of)),
        pg_state,
        Vec::new(),
        audit,
        context,
    )?)
}
