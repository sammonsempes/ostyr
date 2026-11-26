//! Network detection and response: YARA-X (`yr` subprocess) scan of the files Suricata extracted from traffic (T447).


pub mod error;
pub mod event;
#[cfg(unix)]
pub mod exec;
#[cfg(unix)]
pub mod follow;
pub mod model;
pub mod reader;
#[cfg(unix)]
pub mod rules;
#[cfg(unix)]
pub mod scan;
pub mod types;
