//! Usage: `linux_fim render <roles.yaml> <role>`. Writes the Tetragon TracingPolicy of the role to standard output.
use linux_fim::cli::render_command;
use linux_fim::limits::default_limits;
use std::error::Error;
use std::io::stdout;
use std::path::Path;


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.iter().map(String::as_str).collect::<Vec<&str>>().as_slice() {
        [_, "render", table, role] => Ok(render_command(Path::new(table), role, &default_limits(), &mut stdout())?),
        _ => Err("usage: linux_fim render <roles.yaml> <role>".into()),
    }
}
