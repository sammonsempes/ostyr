//! Caddy JSON configuration rendered from a declarative YAML routes file.

#[cfg(unix)]
pub mod admin;
#[cfg(target_os = "linux")]
pub mod apply;
pub mod caddy;
pub mod cadir;
pub mod cli;
pub mod error;
pub mod limits;
pub mod model;
pub mod order;
pub mod render;
pub mod runner;
#[cfg(target_os = "linux")]
pub mod serve;
pub mod tls;
pub mod types;
pub mod validate;
