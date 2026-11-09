//! Missing-update inventory from the output of the native package manager.

pub mod apt;
pub mod dnf;
pub mod error;
pub mod finish;
pub mod limits;
pub mod model;
pub mod scan;
pub mod types;
pub mod validate;
