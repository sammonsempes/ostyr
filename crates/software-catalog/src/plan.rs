//! The pure plan for one device.

use crate::args::arguments;
use crate::error::PlanError;
use crate::limits::Limits;
use crate::model::{Action, ActionKind, Assignment, Catalogue, Entry, Installed, InstalledRow, Plan};
use crate::source::{family_of, manager_of, package_of, version_text};
use crate::text::is_entry_name;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use vuln_match::version::parse_version;


pub fn plan(catalogue: &Catalogue, assignment: &Assignment, installed: &Installed) -> Result<Plan, PlanError> {
    plan_with(catalogue, assignment, installed, &Limits::default())
}


pub fn plan_with(catalogue: &Catalogue, assignment: &Assignment, installed: &Installed, limits: &Limits) -> Result<Plan, PlanError> {
    let wanted = resolve(catalogue, &assignment.install, limits)?;
    let removed = resolve(catalogue, &assignment.remove, limits)?;
    if let Some(entry) = wanted.iter().find(|entry| removed.iter().any(|other| other.name == entry.name)) {
        Err(PlanError::Conflict { name: entry.name.clone() })
    } else {
        let mut actions: Vec<Action> = wanted
            .iter()
            .filter_map(|entry| wanted_action(entry, installed))
            .chain(removed.iter().filter_map(|entry| removal_action(entry, installed)))
            .chain(installed.rows.iter().filter(|row| !in_catalogue(catalogue, row)).map(foreign_action))
            .collect();
        actions.sort_by(|left, right| (left.kind, &left.name, &left.package).cmp(&(right.kind, &right.name, &right.package)));
        let refused_uninstalls = removed.iter().filter(|entry| !entry.uninstall).map(|entry| entry.name.clone()).collect();
        Ok(Plan { actions, refused_uninstalls })
    }
}


pub fn resolve<'catalogue>(catalogue: &'catalogue Catalogue, names: &[String], limits: &Limits) -> Result<Vec<&'catalogue Entry>, PlanError> {
    if names.len() > limits.max_entries {
        Err(PlanError::TooManyNames { limit: limits.max_entries })
    } else {
        names
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<&str>>()
            .into_iter()
            .map(|name| lookup(catalogue, name))
            .collect()
    }
}


pub fn lookup<'catalogue>(catalogue: &'catalogue Catalogue, name: &str) -> Result<&'catalogue Entry, PlanError> {
    if is_entry_name(name) {
        catalogue
            .entries
            .iter()
            .find(|entry| entry.name == name)
            .ok_or_else(|| PlanError::UnknownEntry { name: name.to_string() })
    } else {
        Err(PlanError::InvalidName)
    }
}


pub fn row_of<'installed>(entry: &Entry, installed: &'installed Installed) -> Option<&'installed InstalledRow> {
    installed
        .rows
        .iter()
        .find(|row| row.manager == manager_of(&entry.source) && row.package == package_of(&entry.source))
}


pub fn in_catalogue(catalogue: &Catalogue, row: &InstalledRow) -> bool {
    catalogue
        .entries
        .iter()
        .any(|entry| manager_of(&entry.source) == row.manager && package_of(&entry.source) == row.package)
}


pub fn action_of(kind: ActionKind, entry: &Entry, row: Option<&InstalledRow>) -> Action {
    Action {
        kind,
        name: entry.name.clone(),
        package: package_of(&entry.source).to_string(),
        installed_version: row.map(|found| found.version.clone()),
        target_version: Some(version_text(&entry.version).to_string()),
        arguments: arguments(kind, entry),
    }
}


pub fn wanted_action(entry: &Entry, installed: &Installed) -> Option<Action> {
    match row_of(entry, installed) {
        None => Some(action_of(ActionKind::Install, entry, None)),
        Some(row) => compare(entry, row).map(|kind| action_of(kind, entry, Some(row))),
    }
}


pub fn compare(entry: &Entry, row: &InstalledRow) -> Option<ActionKind> {
    let target = version_text(&entry.version);
    let family = family_of(row.manager);
    if row.version == target {
        None
    } else {
        match (parse_version(family, &row.version), parse_version(family, target)) {
            (Ok(current), Ok(approved)) => match current.cmp(&approved) {
                Ordering::Less => Some(ActionKind::Update),
                Ordering::Greater => Some(ActionKind::NewerThanCatalogue),
                Ordering::Equal => None,
            },
            _ => Some(ActionKind::Unknown),
        }
    }
}


pub fn removal_action(entry: &Entry, installed: &Installed) -> Option<Action> {
    row_of(entry, installed)
        .filter(|_| entry.uninstall)
        .map(|row| action_of(ActionKind::Uninstall, entry, Some(row)))
}


pub fn foreign_action(row: &InstalledRow) -> Action {
    Action {
        kind: ActionKind::NotInCatalogue,
        name: row.package.clone(),
        package: row.package.clone(),
        installed_version: Some(row.version.clone()),
        target_version: None,
        arguments: Vec::new(),
    }
}
