//! Usage: `verify_signature <file-path> [deadline-seconds]`. Opens the file with a deny-write share mode and prints the signature judgement (Windows only).
use std::error::Error;
use std::io::{stdout, Write};


#[cfg(windows)]
fn main() -> Result<(), Box<dyn Error>> {
    use std::time::Duration;
    use sys_windows::signature::verify_signed_file;
    use sys_windows::signer::open_for_verification;
    const ARGUMENT_DEADLINE: usize = 2;
    const DEFAULT_DEADLINE_SECONDS: u64 = 60;
    let path = std::env::args().nth(1).ok_or("usage: verify_signature <file-path> [deadline-seconds]")?;
    let seconds = std::env::args()
        .nth(ARGUMENT_DEADLINE)
        .map_or(Ok(DEFAULT_DEADLINE_SECONDS), |text| text.parse::<u64>())?;
    let file = open_for_verification(std::path::Path::new(&path))?;
    match verify_signed_file(&file, Duration::from_secs(seconds)) {
        Ok(outcome) => writeln!(stdout(), "verdict {outcome:#?}")?,
        Err(error) => writeln!(stdout(), "refused: {error}")?,
    }
    Ok(())
}


#[cfg(not(windows))]
fn main() -> Result<(), Box<dyn Error>> {
    writeln!(stdout(), "verify_signature runs on Windows only")?;
    Ok(())
}
