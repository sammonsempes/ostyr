//! Declarative signed connector packages (spec section 6): the manifest, its validation and the signature check of a package directory.

pub mod bounded;
pub mod cli;
pub mod error;
pub mod keys;
pub mod manifest;
pub mod model;
pub mod package;
#[cfg(unix)]
pub mod scan;
pub mod types;
pub mod verify;
