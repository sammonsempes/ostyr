use crate::catalogue::catalogue_problems;
use crate::error::{DocumentProblems, PlaybookError, ValidationError};
use crate::model::{Catalogue, Playbook, SimulationInput, Trace};
use crate::simulate::simulate;
use crate::validate::playbook_problems;
use core_config::error::ConfigError;
use core_config::load::load_file;
use core_config::reload::{current_config, open_engine, ReloadContext, ReloadEngine, Subscriber};
use core_config::types::{BoxError, ConfigState, LoaderFn, SharedAuditFn};
use response_breakers::breakers::Breakers;
use std::path::{Path, PathBuf};
use std::sync::Arc;


pub const MODULE: &str = "response-playbooks";


pub const RELOAD_REQUEST_ID: &str = "playbooks-reload";


pub const CATALOGUE_DOCUMENT: &str = "catalogue";


pub const VALIDATION_SECTION: &str = "validation";


#[derive(Debug, Clone, PartialEq)]
pub struct LoadedPlaybook {
    pub file: String,
    pub playbook: Playbook,
}


/// The unit of reload: the catalogue and every playbook file, valid together or not at all.
#[derive(Debug, Clone, PartialEq)]
pub struct Bundle {
    pub catalogue: Catalogue,
    pub playbooks: Vec<LoadedPlaybook>,
}


pub struct PlaybookSettings {
    pub catalogue_path: PathBuf,
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
pub fn load_bundle(catalogue: &Path, playbooks: &[PathBuf]) -> Result<Bundle, ConfigError> {
    Ok(Bundle {
        catalogue: load_file(catalogue)?,
        playbooks: playbooks.iter().map(|path| load_playbook(path)).collect::<Result<_, _>>()?,
    })
}


pub fn bundle_loader(catalogue: PathBuf, playbooks: Vec<PathBuf>) -> Box<LoaderFn<Bundle>> {
    Box::new(move || load_bundle(&catalogue, &playbooks))
}


/// One entry per file, in `Debug` form: stable, and the diff of a reload shows which file changed.
pub fn bundle_state(bundle: &Bundle) -> ConfigState {
    let catalogue = (CATALOGUE_DOCUMENT.to_owned(), format!("{:?}", bundle.catalogue));
    let playbooks = bundle
        .playbooks
        .iter()
        .map(|loaded| (format!("playbook.{}", loaded.file), format!("{:?}", loaded.playbook)));
    std::iter::once(catalogue).chain(playbooks).collect()
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
    let engine = open_engine(
        bundle_loader(settings.catalogue_path, settings.playbook_paths),
        bundle_state,
        vec![validation],
        Box::new(move |entry| audit(entry)),
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
    find_playbook(bundle, name).map(|playbook| simulate(playbook, &bundle.catalogue, breakers, input))
}
