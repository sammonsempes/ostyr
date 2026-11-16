//! Usage: `surface_scan --args <scope.yaml>` prints one naabu argument vector per target; `surface_scan --parse <scope.yaml> <naabu-output>` prints the kept results and the counts; `surface_scan <scope.yaml> <naabu-binary> [deadline-seconds]` runs naabu per target (Unix only).
use attack_surface::command::naabu_args;
use attack_surface::model::{Found, Limits};
use attack_surface::results::parse_naabu;
use attack_surface::scope::load_scope;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};
use std::net::SocketAddr;
use std::path::Path;


const ARGS_FLAG: &str = "--args";


const PARSE_FLAG: &str = "--parse";


#[cfg(unix)]
const DEADLINE_SECONDS: u64 = 600;


const OUTPUT_POSITION: usize = 2;


fn found_line(found: &Found) -> String {
    format!("kept {}", SocketAddr::new(found.ip, found.port))
}


#[cfg(unix)]
fn outcome_line(index: usize, outcome: &attack_surface::model::Outcome) -> String {
    use attack_surface::model::Outcome;
    let text = match outcome {
        Outcome::Scanned { kept, counts } => format!(
            "scanned kept={kept} oos={} bad={} dup={} big={} cut={}",
            counts.out_of_scope, counts.malformed, counts.duplicate, counts.oversize_lines, counts.truncated
        ),
        other => format!("{other:?}"),
    };
    attack_surface::text::shown(&format!("target {index}: {text}"))
}


#[cfg(unix)]
fn run_naabu(scope_file: &str, program: &str, seconds: Option<&String>) -> Result<(), Box<dyn Error + Send + Sync>> {
    use attack_surface::run::{scan_scope, summary_line};
    let scope = load_scope(Path::new(scope_file))?;
    let deadline = seconds.map_or(Ok(DEADLINE_SECONDS), |text| text.parse::<u64>())?;
    let report = scan_scope(Path::new(program), &scope, &Limits::default(), std::time::Duration::from_secs(deadline))?;
    let mut out = stdout();
    report
        .targets
        .iter()
        .try_for_each(|target| writeln!(out, "{}", outcome_line(target.index, &target.outcome)))?;
    report.found.iter().try_for_each(|found| writeln!(out, "{}", found_line(found)))?;
    writeln!(out, "{}", summary_line(&report))?;
    Ok(())
}


#[cfg(not(unix))]
fn run_naabu(_scope_file: &str, _program: &str, _seconds: Option<&String>) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("running naabu needs Unix".into())
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let mut out = stdout();
    let first = arguments.first().ok_or("missing scope file")?;
    let second = arguments.get(1).ok_or("missing scope file or naabu binary")?;
    if first == ARGS_FLAG {
        let scope = load_scope(Path::new(second))?;
        scope.targets.iter().try_for_each(|target| -> Result<(), Box<dyn Error + Send + Sync>> {
            let line = naabu_args(&scope, target)?
                .iter()
                .map(|value| value.to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join(" ");
            writeln!(out, "naabu {line}")?;
            Ok(())
        })?;
    } else if first == PARSE_FLAG {
        let output = arguments.get(OUTPUT_POSITION).ok_or("missing naabu output")?;
        let scope = load_scope(Path::new(second))?;
        let report = parse_naabu(&mut File::open(output)?, &scope, &Limits::default())?;
        report.found.iter().try_for_each(|found| writeln!(out, "{}", found_line(found)))?;
        writeln!(out, "counts {:?}", report.counts)?;
    } else {
        run_naabu(first, second, arguments.get(OUTPUT_POSITION))?;
    }
    Ok(())
}
