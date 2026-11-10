//! Usage: `linux_capabilities`. Prints the effective mode and the missing capabilities of this system. Unix only.
#[cfg(unix)]
use agent_linux::capabilities::{detect, effective_mode, missing_names, read_bounded, SYSTEM_ROOT};
#[cfg(unix)]
use std::error::Error;
#[cfg(unix)]
use std::io::{stdout, Write};
#[cfg(unix)]
use std::path::Path;


#[cfg(unix)]
fn main() -> Result<(), Box<dyn Error + Send + Sync>> {
    let capabilities = detect(Path::new(SYSTEM_ROOT), read_bounded);
    let mode = effective_mode(&capabilities);
    writeln!(stdout(), "mode={mode} missing={:?} {capabilities:?}", missing_names(&mode))?;
    Ok(())
}


#[cfg(not(unix))]
fn main() {}
