//! Usage: `surface_scan --args <scope.yaml>` prints one naabu argument vector per target; `surface_scan --parse <scope.yaml> <naabu-output>` prints the kept results and the counts; `surface_scan <scope.yaml> <naabu-binary> [deadline-seconds] [--nameserver <addr:port>] [--total <seconds>]` runs naabu per target (Unix only).
use attack_surface::command::naabu_args;
use attack_surface::model::{Found, Limits};
use attack_surface::results::parse_naabu;
use attack_surface::scope::load_scope;
use attack_surface::text::valid_hostname;
use std::error::Error;
use std::fs::File;
use std::io::{stdout, Write};
use std::net::SocketAddr;
use std::path::Path;


const ARGS_FLAG: &str = "--args";


const PARSE_FLAG: &str = "--parse";


const NAMESERVER_FLAG: &str = "--nameserver";


const TOTAL_FLAG: &str = "--total";


#[cfg(unix)]
const DEADLINE_SECONDS: u64 = 600;


const TOTAL_SECONDS: u64 = 3600;


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
fn run_naabu(
    scope_file: &str,
    program: &str,
    seconds: Option<&String>,
    nameserver: Option<SocketAddr>,
    total: u64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    use attack_surface::run::{scan_scope_resolving, summary_line, Resolver};
    use std::time::{Duration, Instant};
    let scope = load_scope(Path::new(scope_file))?;
    let deadline = seconds.map_or(Ok(DEADLINE_SECONDS), |text| text.parse::<u64>())?;
    let started = Instant::now();
    let resolver = Resolver {
        nameserver,
        resolve: synthetic_checks::dns::dns_resolve,
    };
    let report = scan_scope_resolving(
        Path::new(program),
        &scope,
        &Limits::default(),
        Duration::from_secs(deadline),
        &|| started.elapsed() >= Duration::from_secs(total),
        &resolver,
    )?;
    let mut out = stdout();
    report.targets.iter().try_for_each(|target| -> Result<(), Box<dyn Error + Send + Sync>> {
        writeln!(out, "{}", outcome_line(target.index, &target.outcome))?;
        target
            .runs
            .iter()
            .try_for_each(|run| writeln!(out, "  run {}: {}", run.address, outcome_line(target.index, &run.outcome)))?;
        target
            .refused_addresses
            .iter()
            .try_for_each(|address| writeln!(out, "  refused {address}"))?;
        Ok(())
    })?;
    report.found.iter().try_for_each(|found| writeln!(out, "{}", found_line(found)))?;
    writeln!(out, "{}", summary_line(&report))?;
    Ok(())
}


#[cfg(not(unix))]
fn run_naabu(
    _scope_file: &str,
    _program: &str,
    _seconds: Option<&String>,
    _nameserver: Option<SocketAddr>,
    _total: u64,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    Err("running naabu needs Unix".into())
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let mut arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let nameserver = match arguments.iter().position(|argument| argument == NAMESERVER_FLAG) {
        Some(at) => {
            let value = arguments.get(at + 1).ok_or("missing nameserver address")?.parse::<SocketAddr>()?;
            arguments.drain(at..=at + 1);
            Some(value)
        }
        None => None,
    };
    let total = match arguments.iter().position(|argument| argument == TOTAL_FLAG) {
        Some(at) => {
            let value = arguments.get(at + 1).ok_or("missing total seconds")?.parse::<u64>()?;
            arguments.drain(at..=at + 1);
            value
        }
        None => TOTAL_SECONDS,
    };
    let mut out = stdout();
    let first = arguments.first().ok_or("missing scope file")?;
    let second = arguments.get(1).ok_or("missing scope file or naabu binary")?;
    if first == ARGS_FLAG {
        let scope = load_scope(Path::new(second))?;
        scope.targets.iter().try_for_each(|target| -> Result<(), Box<dyn Error + Send + Sync>> {
            let line = if valid_hostname(target) {
                format!("resolve {target} (the runner passes each checked address to naabu)")
            } else {
                let vector = naabu_args(&scope, target)?
                    .iter()
                    .map(|value| value.to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join(" ");
                format!("naabu {vector}")
            };
            writeln!(out, "{line}")?;
            Ok(())
        })?;
    } else if first == PARSE_FLAG {
        let output = arguments.get(OUTPUT_POSITION).ok_or("missing naabu output")?;
        let scope = load_scope(Path::new(second))?;
        let report = parse_naabu(&mut File::open(output)?, &scope, &Limits::default())?;
        report.found.iter().try_for_each(|found| writeln!(out, "{}", found_line(found)))?;
        writeln!(out, "counts {:?}", report.counts)?;
    } else {
        run_naabu(first, second, arguments.get(OUTPUT_POSITION), nameserver, total)?;
    }
    Ok(())
}
