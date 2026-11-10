use crate::error::DetectionError;
use crate::model::DetectionFile;
use core_config::load::load_file;
use core_config::reload::Subscriber;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine};
use core_config::types::{BoxError, LoaderFn, SharedAuditFn};
use siem_ingest::error::{IngestError, SettingsError};
use siem_ingest::nats_settings::DEFAULT_NATS_CONSUMER;
use siem_ingest::settings::{settings_state, validate_settings, IngestSettings, SECTION};
use std::path::{Path, PathBuf};
use stream_correlation::reload::{load_rules, rules_state};
use stream_correlation::ruleset::RuleSet;


pub fn load_detection_file(path: &Path) -> Result<DetectionFile, DetectionError> {
    Ok(load_file::<DetectionFile>(path)?)
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
    let engine = open_engine(
        Box::new(move || load_file::<DetectionFile>(&path).map(|file| file.ingest)),
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
    Box::new(move || {
        let file = load_file::<DetectionFile>(&path)?;
        load_rules(&file.mapping_file, &file.rule_files)
    })
}


pub fn open_rules_engine(path: PathBuf, audit: Box<SharedAuditFn>, context: ReloadContext) -> Result<ReloadEngine<RuleSet>, DetectionError> {
    Ok(open_engine(rules_loader(path), rules_state, Vec::new(), audit, context)?)
}
