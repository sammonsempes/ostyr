//! Prints the plan: `catalog_plan <catalogue> <assignment> <installed> <available> [apt|dnf]`.

use software_catalog::available::parse_available;
use software_catalog::catalogue::{parse_assignment, parse_catalogue, read_text};
use software_catalog::installed::parse_installed;
use software_catalog::installed_rpm::parse_rpm_installed;
use software_catalog::limits::Limits;
use software_catalog::model::Manager;
use software_catalog::plan::plan;
use std::fs::File;
use std::io::Write;


const MIN_ARGUMENTS: usize = 5;


const MAX_ARGUMENTS: usize = 6;


const AVAILABLE_ARGUMENT: usize = 4;


const MANAGER_ARGUMENT: usize = 5;


const ASSIGNMENT_ARGUMENT: usize = 2;


const INSTALLED_ARGUMENT: usize = 3;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths: Vec<String> = std::env::args().collect();
    if !(MIN_ARGUMENTS..=MAX_ARGUMENTS).contains(&paths.len()) {
        Err("usage: catalog_plan <catalogue> <assignment> <installed> <available> [apt|dnf]")?;
    }
    let manager = match paths.get(MANAGER_ARGUMENT).map(String::as_str) {
        None | Some("apt") => Manager::Apt,
        Some("dnf") => Manager::Dnf,
        Some(_) => Err("manager must be apt or dnf")?,
    };
    let limits = Limits::default();
    let open = |index: usize| -> Result<File, Box<dyn std::error::Error>> {
        let path = paths.get(index).ok_or("missing path")?;
        Ok(File::open(path)?)
    };
    let catalogue = parse_catalogue(&read_text(open(1)?, &limits)?, &limits)?;
    let assignment = parse_assignment(&read_text(open(ASSIGNMENT_ARGUMENT)?, &limits)?, &limits)?;
    let installed = match manager {
        Manager::Dnf => parse_rpm_installed(open(INSTALLED_ARGUMENT)?, &limits)?,
        _ => parse_installed(open(INSTALLED_ARGUMENT)?, &limits)?,
    };
    let available = parse_available(open(AVAILABLE_ARGUMENT)?, manager, &limits)?;
    let result = plan(&catalogue, &assignment, &installed, &available)?;
    let mut out = std::io::stdout();
    writeln!(
        out,
        "actions={} refused_uninstalls={:?} malformed={} over_limit={} not_installed={} available={} available_malformed={}",
        result.actions.len(),
        result.refused_uninstalls,
        installed.malformed,
        installed.over_limit,
        installed.not_installed,
        available.names.len(),
        available.malformed
    )?;
    result
        .actions
        .iter()
        .try_for_each(|action| writeln!(out, "{:?} {} {:?}", action.kind, action.name, action.arguments))?;
    Ok(())
}
