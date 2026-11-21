use crate::error::FimError;
use crate::model::{FimFile, FimPlan, LinuxFile, SourceSettings, MAX_PLANTED_BYTES};
use crate::types::ReadBytesFn;
use core_config::error::ConfigError;
use core_config::load::load_file;
use linux_fim::classify::classify;
use linux_fim::cli::parse_planted;
use linux_fim::limits::default_limits;
use linux_fim::model::FimEvent;
use linux_fim::policy::{policy_names, watch_sets, with_planted};
use linux_fim::roles::load_roles;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::sync::Arc;


/// The most characters of a refusal reason that reach the reload audit.
pub const MAX_REASON_CHARS: usize = 256;


/// The plan from the bytes of the table and of `planted.tsv`, each read once: the role must exist and every planted path be a honeytoken of it or a directory above one.
pub fn plan_from_bytes(role_name: &str, table: &[u8], planted: &[u8]) -> Result<FimPlan, FimError> {
    let limits = default_limits();
    let table_text = std::str::from_utf8(table).map_err(|_| FimError::TableNotUtf8)?;
    let planted_text = std::str::from_utf8(planted).map_err(|_| FimError::PlantedNotUtf8)?;
    let parsed = load_roles(table_text, &limits).map_err(FimError::Table)?;
    let found = parsed.roles.into_iter().find(|candidate| candidate.name == role_name);
    let role = match (role_name.is_empty(), found) {
        (true, _) => Err(FimError::EmptyRole),
        (false, None) => Err(FimError::NoRole),
        (false, Some(role)) => Ok(role),
    }?;
    let identities = parse_planted(planted_text).map_err(FimError::Planted)?;
    let sets = watch_sets(&role);
    let undeclared = identities
        .iter()
        .position(|identity| !sets.tokens.contains(&identity.path) && !sets.token_ancestors.contains(&identity.path));
    match undeclared {
        Some(index) => Err(FimError::Undeclared { entry: index + 1 }),
        None => Ok(FimPlan {
            role: role_name.to_owned(),
            policies: policy_names(role_name),
            sets: with_planted(sets, identities),
            table_sha256: format!("{:x}", Sha256::digest(table)),
            planted_sha256: format!("{:x}", Sha256::digest(planted)),
        }),
    }
}


/// Names the refusal after the file that holds the cause, the reason cut at `MAX_REASON_CHARS`.
pub fn refusal(file: &Path, error: &FimError) -> ConfigError {
    ConfigError::WatchedFile {
        file: file.display().to_string(),
        reason: error.to_string().chars().take(MAX_REASON_CHARS).collect(),
    }
}


/// Reads the table and `planted.tsv` once each (regular files judged on the handle, capped) and builds the plan from those very bytes.
pub fn load_plan(section: &FimFile, read: ReadBytesFn) -> Result<FimPlan, ConfigError> {
    let table = read(&section.table, default_limits().max_table_bytes as u64)?;
    let planted = read(&section.planted, MAX_PLANTED_BYTES)?;
    plan_from_bytes(&section.role, &table, &planted).map_err(|error| refusal(file_of(section, &error), &error))
}


/// The file that holds the cause: `planted.tsv` for its own errors, the table otherwise.
pub fn file_of<'a>(section: &'a FimFile, error: &FimError) -> &'a Path {
    match error {
        FimError::PlantedNotUtf8 | FimError::Planted(_) | FimError::Undeclared { .. } => &section.planted,
        FimError::TableNotUtf8 | FimError::Table(_) | FimError::EmptyRole | FimError::NoRole => &section.table,
    }
}


/// Loads the settings file and, when it has a `fim` section, the plan its files give; any refusal refuses the whole load.
pub fn load_with_plan(path: &Path, read: ReadBytesFn) -> Result<LinuxFile, ConfigError> {
    let file = load_file::<LinuxFile>(path)?;
    let plan = file.fim.as_ref().map(|section| load_plan(section, read)).transpose()?;
    Ok(LinuxFile {
        settings: SourceSettings {
            fim: plan.map(Arc::new),
            ..file.settings
        },
        ..file
    })
}


/// The spool line (kind `agent.fim`) of one classified event; the text fields are the ones linux-fim escaped.
pub fn event_line(event: &FimEvent) -> String {
    json!({"event": {"kind": "agent.fim"}, "agent": {"fim": fields_of(event)}}).to_string()
}


/// The spool line of an export line under the plan, `None` for any other line (also one that is not UTF-8, which the ECS path then counts).
pub fn fim_line(bytes: &[u8], max_line_bytes: u64, plan: &FimPlan) -> Option<String> {
    let text = std::str::from_utf8(bytes)
        .map_err(|error| tracing::debug!(%error, "export line is not UTF-8"))
        .ok()?;
    let limit = usize::try_from(max_line_bytes).unwrap_or(usize::MAX);
    classify(text, limit, &plan.policies, &plan.sets).map(|event| event_line(&event))
}


pub fn fields_of(event: &FimEvent) -> Value {
    match event {
        FimEvent::Write {
            path,
            process,
            name_match,
            mount_ambiguous,
            foreign_mount_ns,
            dentry_path,
        } => json!({
            "type": "write", "path": path, "process": process, "name_match": name_match,
            "mount_ambiguous": mount_ambiguous, "foreign_mount_ns": foreign_mount_ns, "dentry_path": dentry_path,
        }),
        FimEvent::Honeytoken { path, process } => json!({"type": "honeytoken", "path": path, "process": process}),
        FimEvent::Link {
            existing,
            created,
            process,
            honeytoken,
            name_match,
            mount_ambiguous,
            foreign_mount_ns,
            created_dentry,
        } => json!({
            "type": "link", "existing": existing, "created": created, "process": process, "honeytoken": honeytoken,
            "name_match": name_match, "mount_ambiguous": mount_ambiguous, "foreign_mount_ns": foreign_mount_ns,
            "created_dentry": created_dentry,
        }),
        FimEvent::Rename {
            source,
            target,
            process,
            honeytoken,
            mount_ambiguous,
            foreign_mount_ns,
            source_dentry,
            target_dentry,
        } => json!({
            "type": "rename", "source": source, "target": target, "process": process, "honeytoken": honeytoken,
            "mount_ambiguous": mount_ambiguous, "foreign_mount_ns": foreign_mount_ns,
            "source_dentry": source_dentry, "target_dentry": target_dentry,
        }),
        FimEvent::MissingPath { policy, function, process } => {
            json!({"type": "missing_path", "policy": policy, "function": function, "process": process})
        }
        FimEvent::Oversized { policy, bytes } => json!({"type": "oversized", "policy": policy, "bytes": bytes}),
    }
}
