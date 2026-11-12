//! Prints the plan: `catalog_plan <catalogue> <assignment> <installed>`.

use software_catalog::catalogue::{parse_assignment, parse_catalogue, read_text};
use software_catalog::installed::parse_installed;
use software_catalog::limits::Limits;
use software_catalog::plan::plan;
use std::fs::File;
use std::io::Write;


const EXPECTED_ARGUMENTS: usize = 4;


const ASSIGNMENT_ARGUMENT: usize = 2;


const INSTALLED_ARGUMENT: usize = 3;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let paths: Vec<String> = std::env::args().collect();
    if paths.len() != EXPECTED_ARGUMENTS {
        Err("usage: catalog_plan <catalogue> <assignment> <installed>")?;
    }
    let limits = Limits::default();
    let open = |index: usize| -> Result<File, Box<dyn std::error::Error>> {
        let path = paths.get(index).ok_or("missing path")?;
        Ok(File::open(path)?)
    };
    let catalogue = parse_catalogue(&read_text(open(1)?, &limits)?, &limits)?;
    let assignment = parse_assignment(&read_text(open(ASSIGNMENT_ARGUMENT)?, &limits)?, &limits)?;
    let installed = parse_installed(open(INSTALLED_ARGUMENT)?, &limits)?;
    let result = plan(&catalogue, &assignment, &installed)?;
    let mut out = std::io::stdout();
    writeln!(
        out,
        "actions={} refused_uninstalls={:?} malformed={} over_limit={} not_installed={}",
        result.actions.len(),
        result.refused_uninstalls,
        installed.malformed,
        installed.over_limit,
        installed.not_installed
    )?;
    result
        .actions
        .iter()
        .try_for_each(|action| writeln!(out, "{:?} {} {:?}", action.kind, action.name, action.arguments))?;
    Ok(())
}
