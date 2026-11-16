//! `check <file>` prints a summary, `render-chromium <file>` and `render-firefox <file>` the managed policy JSON.

use device_control::extensions::parse_extension_policy;
use device_control::render_extensions::{render_chromium, render_firefox};
use std::fs::File;
use std::io::Write;


const USAGE: &str = "usage: extension_policy check|render-chromium|render-firefox <file>";


const FILE_POSITION: usize = 1;


fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arguments: Vec<String> = std::env::args().skip(1).collect();
    let argument = |position: usize| arguments.get(position).ok_or(USAGE);
    let command = argument(0)?;
    let path = argument(FILE_POSITION)?;
    let policy = parse_extension_policy(&mut File::open(path)?, path)?;
    let mut out = std::io::stdout();
    match command.as_str() {
        "check" => writeln!(
            out,
            "mode={:?} default={:?} extensions={}",
            policy.mode,
            policy.default,
            policy.extensions.len()
        )?,
        "render-chromium" => write!(out, "{}", render_chromium(&policy)?)?,
        "render-firefox" => write!(out, "{}", render_firefox(&policy)?)?,
        _ => Err(USAGE)?,
    }
    Ok(())
}
