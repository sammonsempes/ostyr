use crate::catalogue::catalogue_problems;
use crate::error::{DocumentProblems, PlaybookError, ValidationError};
use crate::model::{Catalogue, Inventory, Playbook, SimulationInput, Trace};
use crate::simulate::simulate;
use crate::validate::playbook_problems;
use core_audit::model::NewEntry;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use response_breakers::breakers::Breakers;
use serde::Serialize;
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::sync::Arc;


pub const MODULE: &str = "response-playbooks";


pub const RELOAD_REQUEST_ID: &str = "playbooks-reload";


pub const CATALOGUE_DOCUMENT: &str = "catalogue";


pub const VALIDATION_SECTION: &str = "validation";


pub const KEY_SEPARATOR: &str = "::";


pub const CHANGED_KEYS_PARAMETER: &str = "changed_settings";


pub const MAX_STATE_DEPTH: usize = 32;


#[derive(Debug, Clone, PartialEq)]
pub struct LoadedPlaybook {
    pub file: String,
    pub playbook: Playbook,
}


/// The unit of reload: the catalogue and every playbook file, valid together or not at all.
#[derive(Debug, Clone, PartialEq)]
pub struct Bundle {
    pub catalogue: Catalogue,
    pub catalogue_file: String,
    pub inventory: Inventory,
    pub inventory_file: String,
    pub playbooks: Vec<LoadedPlaybook>,
}


pub struct PlaybookSettings {
    pub catalogue_path: PathBuf,
    pub inventory_path: PathBuf,
    pub playbook_paths: Vec<PathBuf>,
    pub audit: Arc<SharedAuditFn>,
}


pub fn load_playbook(path: &Path) -> Result<LoadedPlaybook, ConfigError> {
    Ok(LoadedPlaybook {
        file: path.display().to_string(),
        playbook: load_file(path)?,
    })
}


/// Strict parsing of every file: an unknown key is refused with file, line and field path.
pub fn load_bundle(catalogue: &Path, inventory: &Path, playbooks: &[PathBuf]) -> Result<Bundle, ConfigError> {
    Ok(Bundle {
        catalogue: load_file(catalogue)?,
        catalogue_file: catalogue.display().to_string(),
        inventory: load_file(inventory)?,
        inventory_file: inventory.display().to_string(),
        playbooks: playbooks.iter().map(|path| load_playbook(path)).collect::<Result<_, _>>()?,
    })
}


pub fn bundle_loader(catalogue: PathBuf, inventory: PathBuf, playbooks: Vec<PathBuf>) -> Box<LoaderFn<Bundle>> {
    Box::new(move || load_bundle(&catalogue, &inventory, &playbooks))
}


pub fn child_key(parent: &str, name: &str) -> String {
    if parent.ends_with(KEY_SEPARATOR) {
        format!("{parent}{name}")
    } else {
        format!("{parent}.{name}")
    }
}


pub fn children_of<'a>(key: &str, value: &'a Value) -> Vec<(String, &'a Value)> {
    match value {
        Value::Object(map) => map.iter().map(|(name, inner)| (child_key(key, name), inner)).collect(),
        Value::Array(items) => items
            .iter()
            .enumerate()
            .map(|(index, inner)| (child_key(key, &index.to_string()), inner))
            .collect(),
        _ => Vec::new(),
    }
}


/// Every scalar of a document under its own key (`file::steps.0.action`), so that a reload diff names the keys that changed.
pub fn leaves(file: &str, document: &Value) -> Vec<(String, String)> {
    let start = vec![(format!("{file}{KEY_SEPARATOR}"), document)];
    let (frontier, found) = (0..MAX_STATE_DEPTH).fold((start, Vec::new()), |(level, mut found), _| {
        let (inner, scalar): (Vec<_>, Vec<_>) = level.into_iter().partition(|(key, value)| !children_of(key, value).is_empty());
        found.extend(scalar.into_iter().map(|(key, value)| (key, value.to_string())));
        let next = inner.iter().flat_map(|(key, value)| children_of(key, value)).collect();
        (next, found)
    });
    found
        .into_iter()
        .chain(frontier.into_iter().map(|(key, value)| (key, value.to_string())))
        .collect()
}


pub fn document_value<Document: Serialize>(document: &Document) -> Value {
    serde_json::to_value(document)
        .map_err(|failure| {
            tracing::error!(%failure, "document serialisation failed");
            failure.to_string()
        })
        .unwrap_or_else(Value::String)
}


/// One entry per scalar of the catalogue, the inventory and every playbook.
pub fn bundle_state(bundle: &Bundle) -> ConfigState {
    let documents = [
        (bundle.catalogue_file.as_str(), document_value(&bundle.catalogue)),
        (bundle.inventory_file.as_str(), document_value(&bundle.inventory)),
    ]
    .into_iter()
    .chain(
        bundle
            .playbooks
            .iter()
            .map(|loaded| (loaded.file.as_str(), document_value(&loaded.playbook))),
    );
    documents.flat_map(|(file, value)| leaves(file, &value)).collect()
}


/// The JSON array of changed keys; a value that does not parse names no key and is logged.
pub fn changed_keys(text: &str) -> Vec<String> {
    serde_json::from_str(text).unwrap_or_else(|failure| {
        tracing::warn!(%failure, "changed_settings is not a JSON array of strings");
        Vec::new()
    })
}


/// The files named by the diff of a reload entry, so that the audit target is the file that changed.
pub fn retarget(entry: NewEntry, files: &[String]) -> NewEntry {
    let keys = entry
        .parameters
        .get(CHANGED_KEYS_PARAMETER)
        .map(|text| changed_keys(text))
        .unwrap_or_default();
    let changed: Vec<&str> = files
        .iter()
        .filter(|file| {
            let prefix = format!("{file}{KEY_SEPARATOR}");
            keys.iter().any(|key| key.starts_with(&prefix))
        })
        .map(String::as_str)
        .collect();
    if changed.is_empty() {
        entry
    } else {
        NewEntry {
            target: changed.join(","),
            ..entry
        }
    }
}


/// Documents with at least one problem; empty when the bundle is acceptable.
pub fn bundle_problems(bundle: &Bundle) -> Vec<DocumentProblems> {
    std::iter::once(DocumentProblems {
        document: CATALOGUE_DOCUMENT.to_owned(),
        problems: catalogue_problems(&bundle.catalogue),
    })
    .chain(bundle.playbooks.iter().map(|loaded| DocumentProblems {
        document: loaded.file.clone(),
        problems: playbook_problems(&loaded.playbook, &bundle.catalogue),
    }))
    .filter(|found| !found.problems.is_empty())
    .collect()
}


pub fn validate_bundle(bundle: &Bundle) -> Result<(), ValidationError> {
    let found = bundle_problems(bundle);
    if found.is_empty() {
        Ok(())
    } else {
        Err(ValidationError(found))
    }
}


/// Fails when a file does not parse or does not validate: an engine that cannot read its playbooks must not start.
pub fn open_playbooks(settings: PlaybookSettings) -> Result<ReloadEngine<Bundle>, PlaybookError> {
    let known_files: Vec<String> = [&settings.catalogue_path, &settings.inventory_path]
        .into_iter()
        .chain(&settings.playbook_paths)
        .map(|path| path.display().to_string())
        .collect();
    let context = ReloadContext {
        actor_id: MODULE.to_owned(),
        tenant: "all".to_owned(),
        module: MODULE.to_owned(),
        target: settings.catalogue_path.display().to_string(),
        request_id: RELOAD_REQUEST_ID.to_owned(),
    };
    let validation = Subscriber {
        section: VALIDATION_SECTION.to_owned(),
        validate: Box::new(|bundle: &Bundle| validate_bundle(bundle).map_err(BoxError::from)),
        apply: Box::new(|_bundle: &Bundle| ()),
    };
    let audit = settings.audit;
    let files = known_files;
    let engine = open_engine(
        bundle_loader(settings.catalogue_path, settings.inventory_path, settings.playbook_paths),
        bundle_state,
        vec![validation],
        Box::new(move |entry| audit(retarget(entry, &files))),
        context,
    )?;
    validate_bundle(&current_config(&engine))?;
    Ok(engine)
}


/// A playbook is found by its name or by the stem of its file (a name may hold spaces, which a command line cannot).
pub fn find_playbook<'a>(bundle: &'a Bundle, name: &str) -> Option<&'a Playbook> {
    bundle
        .playbooks
        .iter()
        .find(|loaded| loaded.playbook.name == name || Path::new(&loaded.file).file_stem().is_some_and(|stem| stem == name))
        .map(|loaded| &loaded.playbook)
}


/// `None` when no playbook of the current bundle has that name.
pub fn simulate_named(bundle: &Bundle, breakers: &Breakers, name: &str, input: &SimulationInput) -> Option<Trace> {
    find_playbook(bundle, name).map(|playbook| simulate(playbook, &bundle.catalogue, &bundle.inventory, breakers, input))
}
