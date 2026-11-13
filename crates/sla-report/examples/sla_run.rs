use sla_report::model::{Period, SlaFigure};
use sla_report::report::default_report_limits;
use sla_report::run::run_due;
use sla_report::schedule::load_report_file;
use sla_report::types::{FiguresByService, FiguresError};
use std::collections::BTreeMap;
use std::error::Error;
use std::fs;
use std::io::{stdout, Write};
use std::path::Path;
use tempfile::NamedTempFile;


const USAGE: &str = "usage: sla_run <reports.yaml> <figures.json> <out-dir> <now> [<state.json>]";


fn lookup(figures: &FiguresByService, service: &str, period: &Period) -> Result<SlaFigure, FiguresError> {
    let found = figures.get(service).and_then(|by_start| by_start.get(&period.start.to_string()));
    found
        .cloned()
        .ok_or_else(|| format!("no figures for {service} at {}", period.start).into())
}


fn read_state(path: Option<&String>) -> Result<BTreeMap<String, i64>, Box<dyn Error>> {
    match path.filter(|candidate| Path::new(candidate).exists()) {
        Some(candidate) => Ok(serde_json::from_slice(&fs::read(candidate)?)?),
        None => Ok(BTreeMap::new()),
    }
}


fn write_state(path: &str, state: &BTreeMap<String, i64>) -> Result<(), Box<dyn Error>> {
    let directory = Path::new(path)
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = NamedTempFile::new_in(directory)?;
    temporary.write_all(&serde_json::to_vec(state)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path)?;
    Ok(())
}


fn scenario(arguments: &[String]) -> Result<(), Box<dyn Error>> {
    let (reports, figures_path, out_dir, now, state_path) = match arguments {
        [reports, figures, out_dir, now] => Ok((reports, figures, out_dir, now, None)),
        [reports, figures, out_dir, now, state] => Ok((reports, figures, out_dir, now, Some(state))),
        _ => Err(USAGE),
    }?;
    let definitions = load_report_file(Path::new(reports))?.reports;
    let figures: FiguresByService = serde_json::from_slice(&fs::read(figures_path)?)?;
    let last_done = read_state(state_path)?;
    let summary = run_due(
        &definitions,
        &|service, period| lookup(&figures, service, period),
        Path::new(out_dir),
        &last_done,
        now.parse::<i64>()?,
        &default_report_limits(),
    );
    writeln!(
        stdout(),
        "written={} already_written={} failed={} last_done={:?}",
        summary.written,
        summary.already_written,
        summary.failed,
        summary.last_done
    )?;
    state_path.map_or(Ok(()), |path| write_state(path, &summary.last_done))
}


fn main() -> Result<(), Box<dyn Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    scenario(&arguments)
}
