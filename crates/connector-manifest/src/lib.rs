//! Declarative signed connector packages (spec section 6): the manifest, its validation and the signature check of a package directory.

pub mod bounded;
pub mod cli;
#[cfg(target_os = "linux")]
pub mod code_dir;
pub mod elf;
pub mod error;
pub mod keys;
#[cfg(target_os = "linux")]
pub mod kill;
pub mod manifest;
pub mod model;
pub mod openapi;
pub mod output;
pub mod package;
pub mod reply;
#[cfg(target_os = "linux")]
pub mod run;
#[cfg(target_os = "linux")]
pub mod scan;
pub mod skeleton;
pub mod types;
pub mod verify;
