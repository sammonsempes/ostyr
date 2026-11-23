//! Executor of the signed remote shell on the agent: verified order, one-use store, execution queue, banner and session limits.


#[cfg(unix)]
pub mod account;
pub mod banner;
#[cfg(target_os = "linux")]
pub mod cgroup;
#[cfg(target_os = "linux")]
pub mod cleanup;
pub mod compose;
pub mod error;
pub mod model;
pub mod queue;
pub mod session;
#[cfg(target_os = "linux")]
pub mod spawn;
pub mod store;
pub mod types;
pub mod verified;
