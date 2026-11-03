use std::io::{stdin, stdout, BufReader};
use std::process::ExitCode;
use xdrctl::cli::run_reporting;
use xdrctl::http::send_request;


const CONFIG_SUBDIRECTORY: &str = "xdrctl";


fn main() -> std::io::Result<ExitCode> {
    let args: Vec<String> = std::env::args().collect();
    let default_config_dir = dirs::config_dir().map(|dir| dir.join(CONFIG_SUBDIRECTORY));
    run_reporting(
        &args,
        default_config_dir,
        &send_request,
        &mut BufReader::new(stdin()),
        &mut stdout(),
        &mut std::io::stderr(),
    )
}
