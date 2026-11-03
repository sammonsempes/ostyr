use crate::apply::{apply, ApplyContext};
use crate::error::ApplyError;
use crate::plan::{drift, plan, Change, ChangeKind};
use crate::types::{BoxError, ConfigState, Plan};
use core_audit::error::AuditError;
use core_audit::log::{append, open_file_log};
use core_audit::model::{Actor, ActorKind};
use std::fs;
use std::io::{self, Write};
use std::path::Path;
use thiserror::Error;


pub const USAGE: &str = "usage: plan <desired> <state> | drift <desired> <state> | apply <desired> <state> <audit-file> <actor> <justification>";


#[derive(Debug, Error)]
pub enum ApplyCliError {
    #[error("{USAGE}")]
    Usage,
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error(transparent)]
    Audit(#[from] AuditError),
    #[error(transparent)]
    Apply(#[from] ApplyError),
    #[error("{count} change(s) differ from the desired state")]
    Drift { count: usize },
}


pub fn read_entry(entry: fs::DirEntry) -> io::Result<Option<(String, String)>> {
    let path = entry.path();
    if path.is_file() {
        fs::read_to_string(&path).map(|text| Some((entry.file_name().to_string_lossy().into_owned(), text)))
    } else {
        Ok(None)
    }
}


/// Reads every regular file of a directory as one entry: file name to text.
pub fn read_state(dir: &Path) -> io::Result<ConfigState> {
    fs::read_dir(dir)?
        .map(|entry| entry.and_then(read_entry))
        .collect::<io::Result<Vec<_>>>()
        .map(|entries| entries.into_iter().flatten().collect())
}


pub fn apply_to_dir(dir: &Path, change: &Change) -> io::Result<()> {
    match change.kind {
        ChangeKind::Delete => fs::remove_file(dir.join(&change.key)),
        ChangeKind::Create | ChangeKind::Update => fs::write(dir.join(&change.key), &change.after),
    }
}


pub fn write_plan<Output: Write>(changes: &Plan, out: &mut Output) -> io::Result<()> {
    changes
        .iter()
        .try_for_each(|change| write!(out, "{:?} {}\n{}", change.kind, change.key, change.diff))
}


/// Runs one command of the example binary: `plan`, `drift` or `apply` over a directory acting as the real state.
pub fn run<Output: Write>(args: &[&str], out: &mut Output) -> Result<(), ApplyCliError> {
    match args {
        ["plan", desired, state] => {
            write_plan(&plan(&read_state(Path::new(desired))?, &read_state(Path::new(state))?), out).map_err(ApplyCliError::from)
        }
        ["drift", desired, state] => {
            let changes = drift(&read_state(Path::new(desired))?, &read_state(Path::new(state))?);
            write_plan(&changes, out)?;
            if changes.is_empty() {
                Ok(())
            } else {
                Err(ApplyCliError::Drift { count: changes.len() })
            }
        }
        ["apply", desired, state, audit_file, actor, justification] => {
            let wanted = read_state(Path::new(desired))?;
            let changes = plan(&wanted, &read_state(Path::new(state))?);
            let log = open_file_log(Path::new(audit_file))?;
            let context = ApplyContext {
                actor: Actor {
                    kind: ActorKind::User,
                    id: (*actor).to_owned(),
                },
                tenant: "example".to_owned(),
                module: "core-config".to_owned(),
                request_id: "config-apply".to_owned(),
                justification: (*justification).to_owned(),
            };
            let state_dir = Path::new(state);
            let report = apply(
                &changes,
                &wanted,
                &context,
                &mut |entry| append(&log, entry),
                &mut |change| apply_to_dir(state_dir, change).map_err(BoxError::from),
                &mut || read_state(state_dir).map_err(BoxError::from),
            )?;
            writeln!(out, "applied {}", report.applied.len()).map_err(ApplyCliError::from)
        }
        _ => Err(ApplyCliError::Usage),
    }
}
