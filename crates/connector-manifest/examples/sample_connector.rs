use std::io::{stdin, stdout, BufRead, Write};
use std::process::ExitCode;


const BROKEN: u8 = 2;


fn answer() -> std::io::Result<()> {
    let mut line = String::new();
    stdin().lock().read_line(&mut line)?;
    let escaped: String = line.trim().chars().flat_map(char::escape_default).collect();
    writeln!(stdout(), "{{\"status\":\"ok\",\"result\":\"native saw {escaped}\"}}")
}


fn main() -> ExitCode {
    match answer() {
        Ok(()) => ExitCode::SUCCESS,
        Err(_) => ExitCode::from(BROKEN),
    }
}
