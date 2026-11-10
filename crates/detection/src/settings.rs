use crate::error::DetectionError;
use crate::model::{DetectionFile, FixedPaths};
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::Subscriber;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine};
use core_config::types::{BoxError, LoaderFn, SharedAuditFn};
use siem_ingest::error::{IngestError, SettingsError};
use siem_ingest::nats_settings::DEFAULT_NATS_CONSUMER;
use siem_ingest::settings::{settings_state, validate_settings, IngestSettings, SECTION};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use stream_correlation::reload::{load_rules, rules_state};
use stream_correlation::ruleset::RuleSet;


pub fn load_detection_file(path: &Path) -> Result<DetectionFile, DetectionError> {
    Ok(load_file::<DetectionFile>(path)?)
}


pub fn fixed_paths(file: &DetectionFile) -> FixedPaths {
    FixedPaths {
        audit_file: file.audit_file.clone(),
        checkpoint_dir: file.checkpoint_dir.clone(),
        alerts_file: file.alerts_file.clone(),
    }
}


/// The first file read sets the baseline of the start-only settings; a later file that changes one is refused (so audited), never silently ignored.
pub fn check_fixed(baseline: &OnceLock<FixedPaths>, file: DetectionFile) -> Result<DetectionFile, ConfigError> {
    let current = fixed_paths(&file);
    if *baseline.get_or_init(|| current.clone()) == current {
        Ok(file)
    } else {
        Err(ConfigError::WatchedFile {
            file: "audit_file, checkpoint_dir, alerts_file".to_owned(),
            reason: "read at start only, restart the service to change it".to_owned(),
        })
    }
}


pub fn load_checked(path: &Path, baseline: &OnceLock<FixedPaths>) -> Result<DetectionFile, ConfigError> {
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


pub fn validate_ingest(settings: &IngestSettings) -> Result<(), SettingsError> {
    validate_settings(settings).and_then(|()| check_consumer(settings))
}


pub fn ingest_subscriber() -> Subscriber<IngestSettings> {
    Subscriber {
        section: SECTION.to_owned(),
        validate: Box::new(|settings| validate_ingest(settings).map_err(BoxError::from)),
        apply: Box::new(|_| ()),
    }
}


/// The `ingest` section of the service file as the bus adapter's settings; fails on an unreadable file or invalid first settings, a later invalid file is refused and the old settings stay.
pub fn open_ingest(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<IngestSettings>, DetectionError> {
    let baseline = OnceLock::new();
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
pub fn rules_loader(path: PathBuf) -> Box<LoaderFn<RuleSet>> {
    let baseline = OnceLock::new();
    Box::new(move || {
        let file = load_checked(&path, &baseline)?;
        load_rules(&file.mapping_file, &file.rule_files)
    })
}


pub fn open_rules_engine(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<RuleSet>, DetectionError> {
    Ok(open_engine(rules_loader(path), rules_state, Vec::new(), audit, context)?)
}
