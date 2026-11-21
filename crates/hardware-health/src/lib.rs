//! Typed health verdict and measures from the JSON of `smartctl --json=c -a`.

pub mod assess;
pub mod error;
pub mod grammar;
pub mod limits;
pub mod measures;
pub mod model;
pub mod parse;
pub mod redfish;
pub mod redfish_assess;
pub mod redfish_devices;
pub mod redfish_fetch;
#[cfg(unix)]
pub mod smart_exec;
#[cfg(unix)]
pub mod smart_run;
pub mod smart_settings;
pub mod types;
pub mod ups;
pub mod ups_assess;
#[cfg(unix)]
pub mod ups_run;
pub mod ups_settings;
pub mod ups_target;
