use std::error::Error;
use std::fs::File;
use std::io::{stderr, stdout};


fn main() -> Result<(), Box<dyn Error>> {
    let path = std::env::args().nth(1).ok_or("usage: waf_render <routes.yaml>")?;
    let mut input = File::open(path)?;
    waf::cli::render_to(&mut input, &mut stdout(), &mut stderr())?;
    Ok(())
}
