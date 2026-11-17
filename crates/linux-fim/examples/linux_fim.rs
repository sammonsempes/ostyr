//! Usage: `linux_fim render <roles.yaml> <role>` writes the Tetragon TracingPolicy of the role; `linux_fim classify <roles.yaml> <role> <planted.tsv> <capture.jsonl>` writes the event of each line.
use linux_fim::cli::{classify_command, render_command, CaptureFiles};
use linux_fim::limits::{default_limits, MAX_CAPTURE_BYTES};
use std::error::Error;
use std::io::stdout;
use std::path::Path;


fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let arguments: Vec<String> = std::env::args().collect();
    match arguments.iter().map(String::as_str).collect::<Vec<&str>>().as_slice() {
        [_, "render", table, role] => Ok(render_command(Path::new(table), role, &default_limits(), &mut stdout())?),
        [_, "classify", table, role, planted, capture] => {
            let files = CaptureFiles {
                table: Path::new(table),
                planted: Path::new(planted),
                capture: Path::new(capture),
                max_capture_bytes: MAX_CAPTURE_BYTES,
            };
            Ok(classify_command(&files, role, &default_limits(), &mut stdout())?)
        }
        _ => Err("usage: linux_fim render <roles.yaml> <role> | classify <roles.yaml> <role> <planted.tsv> <capture.jsonl>".into()),
    }
}
