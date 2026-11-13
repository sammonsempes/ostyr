//! Usage: `surface_scan --args <scope.yaml>` prints one naabu argument vector per target; `surface_scan <scope.yaml> <naabu-output>` prints the kept results and the counts.
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


fn found_line(found: &Found) -> String {
    format!("kept {}", SocketAddr::new(found.ip, found.port))
}


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    let mut out = stdout();
    let first = arguments.first().ok_or("missing scope file")?;
    let second = arguments.get(1).ok_or("missing scope file or naabu output")?;
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
    } else {
        let scope = load_scope(Path::new(first))?;
        let report = parse_naabu(&mut File::open(second)?, &scope, &Limits::default())?;
        report.found.iter().try_for_each(|found| writeln!(out, "{}", found_line(found)))?;
        writeln!(out, "counts {:?}", report.counts)?;
    }
    Ok(())
}
