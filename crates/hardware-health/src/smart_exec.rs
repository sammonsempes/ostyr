//! Judges the smartctl program before it runs as root, through the shared `core_config::trusted_program` check (Unix only).

use crate::model::FailureClass;
use core_config::trusted_program::{open_trusted_program, same_program, TrustedProgramError};
use rustix::process::geteuid;
use std::os::fd::OwnedFd;
use std::path::Path;
use tracing::debug;


const CHANGED: &str = "program changed after the check";


fn refuse(error: &TrustedProgramError) -> FailureClass {
    debug!(%error, "the smartctl program is refused");
    FailureClass::ProgramRefused
}


/// Opens the program with the shared check and returns the judged handle; every refusal and open failure is `ProgramRefused`.
pub fn check_program_as(program: &Path, trusted_uid: u32) -> Result<OwnedFd, FailureClass> {
    open_trusted_program(program, trusted_uid).map_err(|error| refuse(&error))
}


/// `check_program_as` for the effective user of this process.
pub fn check_program(program: &Path) -> Result<OwnedFd, FailureClass> {
    check_program_as(program, geteuid().as_raw())
}


/// Refuses the run unless the path still names the program the handle holds; an error judging again refuses too.
pub fn check_unchanged(program: &Path, handle: &OwnedFd, trusted_uid: u32) -> Result<(), FailureClass> {
    let same = same_program(handle, program, trusted_uid).inspect_err(|error| debug!(%error, "the smartctl program cannot be judged again"));
    same.unwrap_or(false).then_some(()).ok_or_else(|| {
        debug!(reason = CHANGED, "the smartctl program is refused");
        FailureClass::ProgramRefused
    })
}
