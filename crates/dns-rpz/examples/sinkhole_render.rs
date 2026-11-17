use core_config::load::load_file;
use dns_rpz::policy::{validate_policy, Policy};
use dns_rpz::sinkhole::render_page;
use std::env::args;
use std::error::Error;
use std::io::{stdout, Write};
use std::path::Path;


const USAGE: &str = "usage: sinkhole_render <policy> <host-header>";


fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = args().skip(1);
    let (policy_path, host) = match (arguments.next(), arguments.next()) {
        (Some(policy_path), Some(host)) => (policy_path, host),
        _ => Err(USAGE)?,
    };
    let policy: Policy = load_file(Path::new(&policy_path))?;
    validate_policy(&policy)?;
    let rendered = render_page(policy.sinkhole_page.as_ref(), Some(host.as_bytes()));
    let mut out = stdout();
    writeln!(out, "status {}", rendered.status)?;
    write!(out, "{}", rendered.html)?;
    Ok(())
}
