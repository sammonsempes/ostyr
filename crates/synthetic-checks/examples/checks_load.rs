use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;
use synthetic_checks::load::load_checks;


const USAGE: &str = "usage: checks_load <checks.yaml>";


fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).ok_or(USAGE)?;
    let file = load_checks(Path::new(&path))?;
    writeln!(stdout(), "loaded {} checks", file.checks.len())?;
    Ok(())
}
