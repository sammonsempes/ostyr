use std::error::Error;
use std::fs::File;
use std::io::{stderr, stdout};
use std::path::Path;


const USAGE: &str = "usage: waf_render <routes.yaml> <out_dir>";


fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args().skip(1);
    let path = arguments.next().ok_or(USAGE)?;
    let out_dir = arguments.next().ok_or(USAGE)?;
    let mut input = File::open(path)?;
    waf::cli::render_to(&mut input, &mut stdout(), &mut stderr(), Path::new(&out_dir))?;
    Ok(())
}
