use dhcp_kea::cli::{run, MAX_FOLLOW_POLLS};
use std::env::args;
use std::io::{stderr, stdout};
use std::process::ExitCode;
use std::thread::sleep;


fn main() -> std::io::Result<ExitCode> {
    let arguments: Vec<String> = args().skip(1).collect();
    let borrowed: Vec<&str> = arguments.iter().map(String::as_str).collect();
    run(&borrowed, &mut stdout().lock(), &mut stderr(), MAX_FOLLOW_POLLS, sleep)
}
