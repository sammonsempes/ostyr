//! Declarative signed connector packages (spec section 6): the manifest, its validation and the signature check of a package directory.

pub mod bounded;
pub mod cli;
pub mod error;
pub mod keys;
pub mod manifest;
pub mod model;
pub mod openapi;
pub mod package;
#[cfg(target_os = "linux")]
pub mod scan;
pub mod skeleton;
pub mod types;
pub mod verify;
