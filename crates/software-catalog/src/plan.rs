//! The pure plan for one device.

use crate::args::arguments;
use crate::error::PlanError;
use crate::limits::Limits;
use crate::model::{Action, ActionKind, Assignment, Available, Catalogue, Entry, Installed, InstalledRow, InventoryGap, Manager, Plan};
use crate::source::{family_of, manager_of, package_of, version_text};
use crate::text::is_entry_name;
use std::cmp::Ordering;
use std::collections::BTreeSet;
use vuln_match::version::parse_version;


pub const MALFORMED_REASON: &str = "inventory_malformed";


pub const INCOMPLETE_REASON: &str = "inventory_incomplete";


pub const ABSENT_REASON: &str = "inventory_absent";


pub const DUPLICATE_REASON: &str = "inventory_duplicate";


pub fn plan(catalogue: &Catalogue, assignment: &Assignment, installed: &Installed, available: &Available) -> Result<Plan, PlanError> {
    plan_with(catalogue, assignment, installed, available, &Limits::default())
}


pub fn plan_with(
    catalogue: &Catalogue,
    assignment: &Assignment,
    installed: &Installed,
    available: &Available,
    limits: &Limits,
) -> Result<Plan, PlanError> {
    let wanted = resolve(catalogue, &assignment.install, limits)?;
    let removed = resolve(catalogue, &assignment.remove, limits)?;
    if let Some(entry) = wanted.iter().find(|entry| removed.iter().any(|other| other.name == entry.name)) {
        Err(PlanError::Conflict { name: entry.name.clone() })
    } else {
        let mut actions: Vec<Action> = wanted
            .iter()
            .filter_map(|entry| wanted_action(entry, installed, available))
            .chain(removed.iter().filter_map(|entry| removal_action(entry, installed)))
            .chain(installed.rows.iter().filter(|row| !in_catalogue(catalogue, row)).map(foreign_action))
            .collect();
        actions.sort_by(|left, right| (left.kind, &left.name, &left.package).cmp(&(right.kind, &right.name, &right.package)));
        let refused_uninstalls = removed.iter().filter(|entry| !entry.uninstall).map(|entry| entry.name.clone()).collect();
        let inventory_gaps = gaps_of(installed);
        Ok(Plan {
            actions,
            inventory_gaps,
            refused_uninstalls,
        })
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


pub fn row_of(entry: &Entry, installed: &Installed) -> Option<InstalledRow> {
    let rows: Vec<&InstalledRow> = installed
        .rows
        .iter()
        .filter(|row| row.manager == manager_of(&entry.source) && row.package == package_of(&entry.source))
        .collect();
    let held = rows.iter().any(|row| row.held);
    rows.into_iter()
        .max_by(|left, right| order_rows(left, right))
        .map(|row| InstalledRow { held, ..row.clone() })
}


pub fn row_count(entry: &Entry, installed: &Installed) -> usize {
    installed
        .rows
        .iter()
        .filter(|row| row.manager == manager_of(&entry.source) && row.package == package_of(&entry.source))
        .count()
}


pub fn order_rows(left: &InstalledRow, right: &InstalledRow) -> Ordering {
    let family = family_of(left.manager);
    match (parse_version(family, &left.version), parse_version(family, &right.version)) {
        (Ok(first), Ok(second)) => first.cmp(&second),
        (Err(_), Ok(_)) => Ordering::Greater,
        (Ok(_), Err(_)) => Ordering::Less,
        (Err(_), Err(_)) => Ordering::Equal,
    }
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
        reason: None,
    }
}


pub fn wanted_action(entry: &Entry, installed: &Installed, available: &Available) -> Option<Action> {
    let row = row_of(entry, installed);
    let kind = row.as_ref().map_or(Some(ActionKind::Install), |found| compare(entry, found));
    kind.map(|found| {
        refusal(found, entry, row.as_ref(), installed).unwrap_or_else(|| action_of(gate(found, entry, row.as_ref(), available), entry, row.as_ref()))
    })
}


pub fn refusal(kind: ActionKind, entry: &Entry, row: Option<&InstalledRow>, installed: &Installed) -> Option<Action> {
    gap_reason(installed, manager_of(&entry.source))
        .filter(|_| matches!(kind, ActionKind::Install | ActionKind::Update | ActionKind::Uninstall))
        .map(|reason| Action {
            reason: Some(reason),
            ..action_of(ActionKind::Unknown, entry, row)
        })
}


pub fn gap_reason(installed: &Installed, manager: Manager) -> Option<&'static str> {
    if covers(installed, manager) {
        installed.gaps.get(&manager).and_then(|gap| {
            if gap.over_limit > 0 {
                Some(INCOMPLETE_REASON)
            } else if gap.malformed > 0 {
                Some(MALFORMED_REASON)
            } else {
                None
            }
        })
    } else {
        Some(ABSENT_REASON)
    }
}


pub fn covers(installed: &Installed, manager: Manager) -> bool {
    installed.read_managers.contains(&manager)
}


pub fn is_duplicate(entry: &Entry, installed: &Installed) -> bool {
    installed
        .gaps
        .get(&manager_of(&entry.source))
        .is_some_and(|gap| gap.duplicate_ids.contains(&package_of(&entry.source).to_ascii_lowercase()))
}


pub fn gaps_of(installed: &Installed) -> Vec<InventoryGap> {
    installed
        .gaps
        .iter()
        .filter(|(manager, gap)| covers(installed, **manager) && (gap.over_limit > 0 || gap.malformed > 0 || !gap.duplicate_ids.is_empty()))
        .map(|(manager, gap)| InventoryGap {
            manager: *manager,
            over_limit: gap.over_limit,
            malformed: gap.malformed,
            duplicate_ids: gap.duplicate_ids.len(),
        })
        .collect()
}


pub fn gate(kind: ActionKind, entry: &Entry, row: Option<&InstalledRow>, available: &Available) -> ActionKind {
    match kind {
        ActionKind::Install | ActionKind::Update if !offered(entry, available) => ActionKind::Unavailable,
        ActionKind::Update if row.is_some_and(|found| found.held) => ActionKind::Held,
        other => other,
    }
}


pub fn offered(entry: &Entry, available: &Available) -> bool {
    match manager_of(&entry.source) {
        manager @ (Manager::Apt | Manager::Dnf) => available.names.contains(&(manager, package_of(&entry.source).to_string())),
        Manager::Winget | Manager::Msi => true,
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
    let manager = manager_of(&entry.source);
    match row_of(entry, installed) {
        Some(row) if entry.uninstall => {
            let kind = match (row.held, row_count(entry, installed) > 1) {
                (true, _) => ActionKind::Held,
                (false, true) => ActionKind::UninstallAmbiguous,
                (false, false) => ActionKind::Uninstall,
            };
            let duplicate = (kind == ActionKind::Uninstall && is_duplicate(entry, installed)).then_some(DUPLICATE_REASON);
            let reason = gap_reason(installed, manager).filter(|_| kind == ActionKind::Uninstall).or(duplicate);
            Some(match reason {
                Some(found) => Action {
                    reason: Some(found),
                    ..action_of(ActionKind::Unknown, entry, Some(&row))
                },
                None => action_of(kind, entry, Some(&row)),
            })
        }
        None if entry.uninstall => gap_reason(installed, manager).map(|found| Action {
            reason: Some(found),
            ..action_of(ActionKind::Unknown, entry, None)
        }),
        _ => None,
    }
}


pub fn foreign_action(row: &InstalledRow) -> Action {
    Action {
        kind: ActionKind::NotInCatalogue,
        name: row.package.clone(),
        package: row.package.clone(),
        installed_version: Some(row.version.clone()),
        target_version: None,
        arguments: Vec::new(),
        reason: None,
    }
}
